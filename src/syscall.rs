use libc::{PTRACE_PEEKDATA, PTRACE_POKEDATA, c_void, pid_t};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::Pid;
use std::collections::VecDeque;
use syscalls::Sysno;

#[derive(Debug, Clone)]
pub struct TraceConfig {
    pub rootdir: Option<String>,
    pub binds: Vec<(String, String)>,
    pub loader_shim: bool,
}

#[derive(Debug, Clone)]
struct RewriteAction {
    arg_index: usize,
    new_value: String,
}

pub fn child_setup() {
    ptrace::traceme().expect("ptrace TRACEME failed");
    unsafe { libc::raise(libc::SIGSTOP) };
}

pub fn trace_loop(child: Pid, config: TraceConfig) {
    let _ = waitpid(child, None);

    ptrace::setoptions(child, ptrace::Options::PTRACE_O_TRACESYSGOOD).expect("setoptions failed");

    let mut in_syscall = false;
    let mut injected: VecDeque<(u64, usize)> = VecDeque::new();

    loop {
        if ptrace::syscall(child, None).is_err() {
            break;
        }

        match waitpid(child, None) {
            Ok(WaitStatus::PtraceSyscall(_)) => {
                let mut regs = unsafe { get_regs(child.as_raw()) };
                let nr = syscall_number(&regs) as u32;

                if !in_syscall {
                    if let Some(action) = maybe_rewrite_path(child, &mut regs, nr, &config) {
                        match inject_rewritten_path(child, &mut regs, nr, &action, &config) {
                            Ok(allocs) => injected.extend(allocs),
                            Err(e) => eprintln!("[tinytrace] rewrite error: {e}"),
                        }
                    }
                    in_syscall = true;
                } else {
                    while let Some((addr, len)) = injected.pop_front() {
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
            Err(nix::Error::ECHILD) => break,
            _ => {}
        }
    }
}

fn maybe_rewrite_path(
    child: Pid,
    regs: &mut Regs,
    sysno: u32,
    config: &TraceConfig,
) -> Option<RewriteAction> {
    let arg_index = path_arg_index(sysno)?;
    let orig_addr = get_arg(regs, arg_index);
    if orig_addr == 0 {
        return None;
    }

    let orig = read_cstr_from_child(child.as_raw(), orig_addr, 4096).ok()?;
    let rewritten = rewrite_path(&orig, config)?;

    Some(RewriteAction {
        arg_index,
        new_value: rewritten,
    })
}

fn rewrite_path(path: &str, config: &TraceConfig) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }

    for (host, guest) in &config.binds {
        let guest_norm = guest.trim_end_matches('/');
        if path == guest_norm || path.starts_with(&format!("{guest_norm}/")) {
            let suffix = path.strip_prefix(guest_norm).unwrap_or("");
            return Some(format!("{}{}", host.trim_end_matches('/'), suffix));
        }
    }

    config.rootdir.as_ref().map(|root| {
        format!(
            "{}/{}",
            root.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    })
}

fn inject_rewritten_path(
    child: Pid,
    regs: &mut Regs,
    sysno: u32,
    action: &RewriteAction,
    config: &TraceConfig,
) -> Result<Vec<(u64, usize)>, Errno> {
    let mut allocs = Vec::new();
    let remote = remote_mmap(child, action.new_value.len() + 1)?;
    write_cstr_to_child(child.as_raw(), remote, &action.new_value)?;
    set_arg(regs, action.arg_index, remote);
    allocs.push((remote, action.new_value.len() + 1));

    if config.loader_shim && sysno == Sysno::execve as u32 {
        if let Some((loader, target)) = loader_paths(config, &action.new_value) {
            let loader_remote = remote_mmap(child, loader.len() + 1)?;
            write_cstr_to_child(child.as_raw(), loader_remote, &loader)?;
            allocs.push((loader_remote, loader.len() + 1));

            let target_remote = remote_mmap(child, target.len() + 1)?;
            write_cstr_to_child(child.as_raw(), target_remote, &target)?;
            allocs.push((target_remote, target.len() + 1));

            let argv_addr = get_arg(regs, 1);
            let original_argv = read_ptr_array(child.as_raw(), argv_addr, 256)?;
            let mut new_argv = vec![loader_remote, target_remote];
            new_argv.extend(original_argv.into_iter().skip(1));
            let argv_remote = write_ptr_array(child.as_raw(), child, &new_argv)?;
            allocs.push((argv_remote.0, argv_remote.1));

            set_arg(regs, 0, loader_remote);
            set_arg(regs, 1, argv_remote.0);
        }
    }

    unsafe { set_regs(child.as_raw(), regs) };
    Ok(allocs)
}

fn loader_paths(config: &TraceConfig, rewritten_exec: &str) -> Option<(String, String)> {
    let root = config.rootdir.as_ref()?;
    let candidates = ["/lib64/ld-linux-x86-64.so.2", "/lib/ld-linux-aarch64.so.1"];
    for c in candidates {
        let candidate = format!("{}{}", root.trim_end_matches('/'), c);
        if std::path::Path::new(&candidate).exists() {
            return Some((candidate, rewritten_exec.to_string()));
        }
    }
    None
}

fn path_arg_index(sysno: u32) -> Option<usize> {
    match Sysno::from(sysno) {
        Sysno::execve | Sysno::chdir | Sysno::chroot | Sysno::open => Some(0),
        Sysno::openat | Sysno::mkdirat | Sysno::newfstatat | Sysno::unlinkat | Sysno::faccessat => {
            Some(1)
        }
        _ => None,
    }
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct Regs {
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
}

#[cfg(target_arch = "aarch64")]
const NT_PRSTATUS: libc::c_ulong = 1;

#[cfg(target_arch = "aarch64")]
unsafe fn get_regs(pid: pid_t) -> Regs {
    let mut regs: Regs = std::mem::zeroed();
    let mut io = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: std::mem::size_of::<Regs>(),
    };
    if libc::ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &mut io) != 0 {
        panic!("PTRACE_GETREGSET failed");
    }
    regs
}

#[cfg(target_arch = "aarch64")]
unsafe fn set_regs(pid: pid_t, regs: &Regs) {
    libc::ptrace(
        libc::PTRACE_SETREGS,
        pid,
        std::ptr::null_mut::<c_void>(),
        regs as *const _ as *mut c_void,
    );
}

#[cfg(target_arch = "aarch64")]
fn syscall_number(regs: &Regs) -> u64 {
    regs.regs[8]
}

#[cfg(target_arch = "aarch64")]
fn get_arg(regs: &Regs, idx: usize) -> u64 {
    regs.regs[idx]
}

#[cfg(target_arch = "aarch64")]
fn set_arg(regs: &mut Regs, idx: usize, value: u64) {
    regs.regs[idx] = value;
}

#[cfg(target_arch = "x86_64")]
type Regs = libc::user_regs_struct;

#[cfg(target_arch = "x86_64")]
unsafe fn get_regs(pid: pid_t) -> Regs {
    ptrace::getregs(Pid::from_raw(pid)).expect("PTRACE_GETREGS failed")
}

#[cfg(target_arch = "x86_64")]
unsafe fn set_regs(pid: pid_t, regs: &Regs) {
    ptrace::setregs(Pid::from_raw(pid), *regs).expect("PTRACE_SETREGS failed")
}

#[cfg(target_arch = "x86_64")]
fn syscall_number(regs: &Regs) -> u64 {
    regs.orig_rax
}

#[cfg(target_arch = "x86_64")]
fn get_arg(regs: &Regs, idx: usize) -> u64 {
    match idx {
        0 => regs.rdi,
        1 => regs.rsi,
        2 => regs.rdx,
        3 => regs.r10,
        4 => regs.r8,
        5 => regs.r9,
        _ => 0,
    }
}

#[cfg(target_arch = "x86_64")]
fn set_arg(regs: &mut Regs, idx: usize, value: u64) {
    match idx {
        0 => regs.rdi = value,
        1 => regs.rsi = value,
        2 => regs.rdx = value,
        3 => regs.r10 = value,
        4 => regs.r8 = value,
        5 => regs.r9 = value,
        _ => {}
    }
}

fn remote_mmap(child: Pid, size: usize) -> Result<u64, Errno> {
    let mut regs = unsafe { get_regs(child.as_raw()) };
    let saved = regs;

    set_arg(&mut regs, 0, 0);
    set_arg(&mut regs, 1, size as u64);
    set_arg(&mut regs, 2, (libc::PROT_READ | libc::PROT_WRITE) as u64);
    set_arg(
        &mut regs,
        3,
        (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS) as u64,
    );
    set_arg(&mut regs, 4, !0u64);
    set_arg(&mut regs, 5, 0);
    set_syscall_number(&mut regs, Sysno::mmap as u64);

    unsafe { set_regs(child.as_raw(), &regs) };
    ptrace::syscall(child, None).ok();
    let _ = waitpid(child, None);

    let regs = unsafe { get_regs(child.as_raw()) };
    let addr = syscall_retval(&regs);

    unsafe { set_regs(child.as_raw(), &saved) };
    Ok(addr)
}

fn remote_munmap(child: Pid, addr: u64, size: usize) -> Result<(), Errno> {
    let mut regs = unsafe { get_regs(child.as_raw()) };
    let saved = regs;

    set_arg(&mut regs, 0, addr);
    set_arg(&mut regs, 1, size as u64);
    set_syscall_number(&mut regs, Sysno::munmap as u64);

    unsafe { set_regs(child.as_raw(), &regs) };
    ptrace::syscall(child, None).ok();
    let _ = waitpid(child, None);
    unsafe { set_regs(child.as_raw(), &saved) };
    Ok(())
}

#[cfg(target_arch = "aarch64")]
fn syscall_retval(regs: &Regs) -> u64 {
    regs.regs[0]
}
#[cfg(target_arch = "x86_64")]
fn syscall_retval(regs: &Regs) -> u64 {
    regs.rax
}

#[cfg(target_arch = "aarch64")]
fn set_syscall_number(regs: &mut Regs, nr: u64) {
    regs.regs[8] = nr;
}
#[cfg(target_arch = "x86_64")]
fn set_syscall_number(regs: &mut Regs, nr: u64) {
    regs.orig_rax = nr;
}

fn read_ptr_array(pid: pid_t, addr: u64, max: usize) -> Result<Vec<u64>, Errno> {
    let mut out = Vec::new();
    let step = std::mem::size_of::<u64>() as u64;
    for i in 0..max {
        let p = read_word(pid, addr + (i as u64 * step))?;
        if p == 0 {
            break;
        }
        out.push(p);
    }
    Ok(out)
}

fn write_ptr_array(pid: pid_t, child: Pid, values: &[u64]) -> Result<(u64, usize), Errno> {
    let size = (values.len() + 1) * std::mem::size_of::<u64>();
    let remote = remote_mmap(child, size)?;
    for (i, val) in values.iter().enumerate() {
        write_word(pid, remote + (i * 8) as u64, *val)?;
    }
    write_word(pid, remote + (values.len() * 8) as u64, 0)?;
    Ok((remote, size))
}

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

fn write_word(pid: pid_t, addr: u64, value: u64) -> Result<(), Errno> {
    let rc = unsafe {
        libc::ptrace(
            PTRACE_POKEDATA,
            pid,
            addr as *mut c_void,
            value as *mut c_void,
        )
    };
    if rc != 0 {
        let e = Errno::last();
        if e != Errno::UnknownErrno {
            return Err(e);
        }
    }
    Ok(())
}
