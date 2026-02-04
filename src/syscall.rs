use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::sys::signal::Signal;
use nix::unistd::Pid;
use syscalls::Sysno;
use libc::{iovec, pid_t, c_void, PTRACE_GETREGSET};
use nix::errno::Errno;
use nix::Error;

/// aarch64 register struct for NT_PRSTATUS
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Aarch64Regs {
    pub regs: [u64; 31], // x0-x30
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

/// constant for general-purpose registers
const NT_PRSTATUS: libc::c_ulong = 1;

/// setup child for tracing
pub fn child_setup() {
    ptrace::traceme().expect("ptrace TRACEME failed");
    unsafe { libc::raise(libc::SIGSTOP) };
}

/// fetch registers using raw ptrace
pub unsafe fn get_regs(pid: pid_t) -> Aarch64Regs {
    let mut regs: Aarch64Regs = std::mem::zeroed();
    let mut io = iovec {
        iov_base: &mut regs as *mut _ as *mut c_void,
        iov_len: std::mem::size_of::<Aarch64Regs>(),
    };
    let ret = libc::ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &mut io);
    if ret != 0 {
        panic!("PTRACE_GETREGSET failed");
    }
    regs
}

pub fn trace_loop(child: Pid, rootdir: Option<String>) {
    // wait for initial SIGSTOP
    let _ = waitpid(child, None);

    unsafe { ptrace::setoptions(child, ptrace::Options::PTRACE_O_TRACESYSGOOD).unwrap(); }

    let mut in_syscall = false;

    loop {
        // safe ptrace::syscall call
        if let Err(e) = ptrace::syscall(child, None) {
            if let Error::ECHILD = e {
                eprintln!("child disappeared (ECHILD) during ptrace::syscall");
                break;
            } else {
                eprintln!("ptrace::syscall failed: {:?}", e);
                break;
            }
        }

        match waitpid(child, None) {
            Ok(WaitStatus::Stopped(_, sig)) => {
                if (sig as i32) & 0x80 == 0 { continue; }

                let mut regs = unsafe { get_regs(child.as_raw()) };
                let nr = syscall_number(&regs);

                // === TRACE SYSCALLS ===
                if !in_syscall {
                  // syscall entry
                  let nr = syscall_number(&regs);
                  println!("→ syscall {} {}", nr, syscall_name(nr));
              
                  // rewrite path if needed
                  if let Some(root) = &rootdir {
                      match Sysno::from(nr as u32) {
                          Sysno::openat | Sysno::execve => {
                              rewrite_path_in_child(child, &mut regs, root);
                              unsafe { set_regs(child.as_raw() as pid_t, &regs); }
                          }
                          _ => {}
                      }
                  }
                
                    in_syscall = true;
                  } else {
                      // syscall exit
                      let ret = syscall_ret(&regs);
                      println!("← return {}", ret);
                      in_syscall = false;
                  }
                }
            Ok(WaitStatus::Exited(_, code)) => { println!("child exited ({})", code); break; }
            Ok(WaitStatus::Signaled(_, sig, _)) => { println!("child killed by {:?}", sig); break; }
            Err(Error::ECHILD) => { eprintln!("child disappeared (ECHILD)"); break; }
            _ => continue,
        }
    }
}

unsafe fn set_regs(pid: pid_t, regs: &Aarch64Regs) {
    libc::ptrace(
        libc::PTRACE_SETREGS,
        pid,
        std::ptr::null_mut::<c_void>(),
        regs as *const _ as *mut c_void,
    );
}

/// get syscall number from regs
fn syscall_number(regs: &Aarch64Regs) -> u64 { regs.regs[8] }

/// get syscall return value
fn syscall_ret(regs: &Aarch64Regs) -> u64 { regs.regs[0] }

/// get syscall name
fn syscall_name(nr: u64) -> String {
    if let Ok(n) = u32::try_from(nr) {
        format!("{:?}", Sysno::from(n))
    } else {
        format!("unknown({})", nr)
    }
}

/// Intercept and rewrite path in child memory
fn rewrite_path_in_child(child: Pid, regs: &mut Aarch64Regs, root: &str) {
    use libc::{c_void, pid_t};
    use std::ffi::CString;

    // aarch64: first arg is in x0
    let path_addr = regs.regs[0];
    let orig_path = read_cstr_from_child(child.as_raw() as pid_t, path_addr);

    // prepend root
    let new_path = format!("{}/{}", root, orig_path.strip_prefix("/").unwrap_or(&orig_path));
    write_cstr_to_child(child.as_raw() as pid_t, path_addr, &new_path);
}

/// read a null-terminated string from child memory
fn read_cstr_from_child(pid: libc::pid_t, addr: u64) -> String {
    let mut bytes = Vec::new();
    let mut offset = 0;
    loop {
        let word = unsafe { libc::ptrace(libc::PTRACE_PEEKDATA, pid, (addr + offset as u64) as *mut c_void, 0) } as u64;
        for i in 0..8 {
            let b = ((word >> (i*8)) & 0xFF) as u8;
            if b == 0 { return String::from_utf8_lossy(&bytes).to_string(); }
            bytes.push(b);
        }
        offset += 8;
    }
}

/// write a null-terminated string into child memory
fn write_cstr_to_child(pid: libc::pid_t, addr: u64, s: &str) {
    let bytes = s.as_bytes();
    let mut offset = 0;
    while offset < bytes.len() {
        let mut word: u64 = 0;
        for i in 0..8 {
            if offset + i < bytes.len() {
                word |= (bytes[offset + i] as u64) << (i*8);
            }
        }
        unsafe { libc::ptrace(libc::PTRACE_POKEDATA, pid, (addr + offset as u64) as *mut c_void, word as *mut c_void); }
        offset += 8;
    }
    // null terminate
    unsafe { libc::ptrace(libc::PTRACE_POKEDATA, pid, (addr + bytes.len() as u64) as *mut c_void, 0 as *mut c_void); }
}