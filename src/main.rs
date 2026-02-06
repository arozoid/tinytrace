use nix::unistd::{fork, ForkResult, execvp};
use nix::sys::wait::{waitpid, WaitStatus};
use std::ffi::CString;
use clap::Parser;

mod syscall;

/// Tinytrace: simple syscall tracer
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Program to execute and trace
    #[arg()]
    program: String,

    /// Arguments for the program
    #[arg(last = true)]
    args: Vec<String>,
    
    /// Optional rootdir for rootless overlay
    #[arg(short = 'r', long)]
    rootdir: Option<String>,
}

fn main() {
    let args = Args::parse();

    match unsafe { fork() }.expect("fork failed") {
        ForkResult::Child => {
            // setup ptrace in child
            syscall::child_setup();

            // prepare exec arguments
            let prog_c = CString::new(args.program.clone()).unwrap();
            let mut cargs: Vec<CString> = Vec::with_capacity(args.args.len() + 1);
            cargs.push(prog_c.clone());
            for a in &args.args {
                cargs.push(CString::new(a.as_str()).unwrap());
            }

            execvp(&prog_c, &cargs).expect("exec failed");
            unreachable!();
        }
        ForkResult::Parent { child } => {
            // trace syscalls in parent
            syscall::trace_loop(child, args.rootdir);
        }
    }
}
