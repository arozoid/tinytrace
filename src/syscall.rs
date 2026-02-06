use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use syscalls::Sysno;
use libc::{c_void, pid_t, iovec, PTRACE_GETREGSET, PTRACE_PEEKDATA, PTRACE_POKEDATA};
use nix::errno::Errno;
use std::collections::VecDeque;
use nix::sys::ptrace::Options;

/*
FIXED TRACE LOOP + MMAP INJECTION (AARCH64)
=========================================

What was wrong before:
- we relied on SIGTRAP || (sig & 0x80) which *collapses entry/exit*
- first syscall looked fine, then state desynced

What is fixed now:
- ONLY treat (SIGTRAP | 0x80) as syscall-stop
- explicit entry/exit toggle
- ptrace::syscall() is issued exactly once per loop iteration
- mmap/munmap injection is balanced and reclaimed
*/

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Aarch64Regs {
    pub regs: [u64; 31], // x0-x30
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

#[cfg(target_arch = "aarch64")]
const NT_PRSTATUS: libc::c_ulong = 1;

#[inline(always)]
fn dbg(msg: &str) {
    eprintln!("[tinytrace] {msg}");
}

#[inline(always)]
fn dbg_sys(sysno: u64, phase: &str) {
    let name = Sysno::from(sysno as u32);
    eprintln!("[tinytrace] {} syscall {:?} ({})", phase, name, sysno);
}

// ---------------- Child setup ----------------

pub fn child_setup() {
    dbg("child_setup: TRACEME + SIGSTOP");
    ptrace::traceme().expect("ptrace TRACEME failed");
    unsafe { libc::raise(libc::SIGSTOP) };
}

// ---------------- Trace loop ----------------

pub fn trace_loop(child: Pid, rootdir: Option<String>) {
    dbg("trace_loop: waiting for SIGSTOP");
    let _ = waitpid(child, None);

    ptrace::setoptions(
        child,
        ptrace::Options::PTRACE_O_TRACESYSGOOD,
    )
    .expect("setoptions failed");

    let mut in_syscall = false;
    let mut injected: VecDeque<(u64, usize)> = VecDeque::new();

    loop {
        // resume until next syscall stop
        if ptrace::syscall(child, None).is_err() {
            dbg("ptrace::syscall failed");
            break;
        }

        match waitpid(child, None) {
            Ok(WaitStatus::Stopped(_, sig)) if sig == Signal::SIGTRAP | Signal::from_c_int(0x80).unwrap() => {
                let mut regs = unsafe { get_regs(child.as_raw()) };
                let nr = syscall_number(&regs);

                if !in_syscall {
                    dbg_sys(nr, "→ entry");

                    if let Some(root) = &rootdir {
                        match maybe_rewrite_path_mmap(child, &mut regs, nr as u32, root) {
                            Ok(Some((addr, len))) => {
                                eprintln!("[tinytrace] mmap injected @ {:#x} ({} bytes)", addr, len);
                                injected.push_back((addr, len));
                            }
                            Ok(None) => dbg("no rewrite"),
                            Err(e) => eprintln!("[tinytrace] rewrite error: {e}"),
                        }
                    }

                    in_syscall = true;
                } else {
                    dbg_sys(nr, "← exit");

                    // reclaim ALL mmaps from this syscall
                    while let Some((addr, len)) = injected.pop_front() {
                        eprintln!("[tinytrace] munmap {:#x} ({len})", addr);
                        let _ = remote_munmap(child, addr, len);
                    }

                    in_syscall = false;
                }
            }

            Ok(WaitStatus::Exited(_, code)) => {
                eprintln!("[tinytrace] child exited ({code})");
                break;
            }

            Ok(WaitStatus::Signaled(_, sig, _)) => {
                eprintln!("[tinytrace] child killed by {sig:?}");
                break;
            }

            Err(nix::Error::ECHILD) => {
                dbg("ECHILD – done");
                break;
            }

            _ => {}
        }
    }
}

// ---------------- Registers ----------------

#[cfg(target_arch = "aarch64")]
unsafe fn get_regs(pid: pid_t) -> Aarch64Regs {
    let mut regs: Aarch64Regs = std::mem::zeroed();
    let mut io = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: std::mem::size_of::<Aarch64Regs>(),
    };

    if libc::ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &mut io) != 0 {
        panic!("PTRACE_GETREGSET failed");
    }
    regs
}

#[cfg(target_arch = "aarch64")]
unsafe fn set_regs(pid: pid_t, regs: &Aarch64Regs) {
    libc::ptrace(
        libc::PTRACE_SETREGS,
        pid,
        std::ptr::null_mut::<c_void>(),
        regs as *const _ as *mut c_void,
    );
}

#[cfg(target_arch = "aarch64")]
fn syscall_number(regs: &Aarch64Regs) -> u64 {
    regs.regs[8]
}

// ---------------- Path rewrite via mmap ----------------

fn maybe_rewrite_path_mmap(
    child: Pid,
    regs: &mut Aarch64Regs,
    sysno: u32,
    rootdir: &str,
) -> Result<Option<(u64, usize)>, Errno> {
    let path_reg = match Sysno::from(sysno) {
        Sysno::execve => 0,
        Sysno::openat => 1,
        _ => return Ok(None),
    };

    let orig_addr = regs.regs[path_reg];
    if orig_addr == 0 {
        return Ok(None);
    }

    let orig = read_cstr_from_child(child.as_raw(), orig_addr, 4096)?;
    eprintln!("[tinytrace] original path: {orig}");

    if !orig.starts_with('/') {
        return Ok(None);
    }

    let rewritten = format!(
        "{}/{}",
        rootdir.trim_end_matches('/'),
        orig.trim_start_matches('/')
    );

    eprintln!("[tinytrace] rewritten path: {rewritten}");

    let size = rewritten.len() + 1;
    let remote = remote_mmap(child, size)?;
    write_cstr_to_child(child.as_raw(), remote, &rewritten)?;

    regs.regs[path_reg] = remote;
    unsafe { set_regs(child.as_raw(), regs) };

    Ok(Some((remote, size)))
}

// ---------------- Remote mmap / munmap ----------------

fn remote_mmap(child: Pid, size: usize) -> Result<u64, Errno> {
    eprintln!("[tinytrace] remote mmap({size})");

    let mut regs = unsafe { get_regs(child.as_raw()) };
    let saved = regs;

    regs.regs[0] = 0;
    regs.regs[1] = size as u64;
    regs.regs[2] = (libc::PROT_READ | libc::PROT_WRITE) as u64;
    regs.regs[3] = (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64;
    regs.regs[4] = !0u64;
    regs.regs[5] = 0;
    regs.regs[8] = Sysno::mmap as u64;

    unsafe { set_regs(child.as_raw(), &regs) };
    ptrace::syscall(child, None).ok();
    let _ = waitpid(child, None);

    let regs = unsafe { get_regs(child.as_raw()) };
    let addr = regs.regs[0];

    unsafe { set_regs(child.as_raw(), &saved) };
    Ok(addr)
}

fn remote_munmap(child: Pid, addr: u64, size: usize) -> Result<(), Errno> {
    let mut regs = unsafe { get_regs(child.as_raw()) };
    let saved = regs;

    regs.regs[0] = addr;
    regs.regs[1] = size as u64;
    regs.regs[8] = Sysno::munmap as u64;

    unsafe { set_regs(child.as_raw(), &regs) };
    ptrace::syscall(child, None).ok();
    let _ = waitpid(child, None);

    unsafe { set_regs(child.as_raw(), &saved) };
    Ok(())
}

// ---------------- Memory helpers ----------------

fn read_cstr_from_child(pid: pid_t, addr: u64, max_len: usize) -> Result<String, Errno> {
    let mut out = Vec::new();
    let mut off = 0usize;

    while out.len() < max_len {
        let word = unsafe {
            libc::ptrace(
                PTRACE_PEEKDATA,
                pid,
                (addr + off as u64) as *mut c_void,
                std::ptr::null_mut::<c_void>(),
            )
        };

        if word == -1 {
            let e = Errno::last();
            if e != Errno::UnknownErrno {
                return Err(e);
            }
        }

        for b in (word as u64).to_le_bytes() {
            if b == 0 {
                return Ok(String::from_utf8_lossy(&out).into_owned());
            }
            out.push(b);
            if out.len() >= max_len {
                break;
            }
        }
        off += 8;
    }

    Err(Errno::ENAMETOOLONG)
}

fn write_cstr_to_child(pid: pid_t, addr: u64, s: &str) -> Result<(), Errno> {
    let bytes = s.as_bytes();
    let total = bytes.len() + 1;
    let mut offset = 0usize;

    while offset < total {
        let mut word = read_word(pid, addr + offset as u64)?;
        for i in 0..8 {
            let idx = offset + i;
            let byte = if idx < bytes.len() {
                bytes[idx]
            } else if idx == bytes.len() {
                0
            } else {
                break;
            };
            word &= !(0xFFu64 << (i * 8));
            word |= (byte as u64) << (i * 8);
        }
        unsafe {
            libc::ptrace(
                PTRACE_POKEDATA,
                pid,
                (addr + offset as u64) as *mut c_void,
                word as *mut c_void,
            )
        };
        offset += 8;
    }
    Ok(())
}

fn read_word(pid: pid_t, addr: u64) -> Result<u64, Errno> {
    let val = unsafe {
        libc::ptrace(
            PTRACE_PEEKDATA,
            pid,
            addr as *mut c_void,
            std::ptr::null_mut::<c_void>(),
        )
    };
    if val == -1 {
        let e = Errno::last();
        if e != Errno::UnknownErrno {
            return Err(e);
        }
    }
    Ok(val as u64)
}
