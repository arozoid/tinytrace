use clap::Parser;
use nix::unistd::{ForkResult, execvp, fork};
use std::ffi::CString;

mod syscall;

/// Tinytrace: simple syscall tracer
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Program to execute and trace
    #[arg()]
    program: String,

    /// Arguments for the program
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,

    /// Optional rootdir for rootless overlay
    #[arg(short = 'r', long)]
    rootdir: Option<String>,

    /// Bind mounts in form /host/path:/guest/path (repeatable)
    #[arg(short = 'b', long = "bind")]
    binds: Vec<String>,

    /// Run dynamic binaries through a loader shim under rootdir
    #[arg(long)]
    loader_shim: bool,
}

#[allow(unreachable_code)]
fn main() {
    let args = Args::parse();
    let binds = args
        .binds
        .iter()
        .filter_map(|spec| spec.split_once(':'))
        .map(|(host, guest)| (host.to_string(), guest.to_string()))
        .collect();

    let config = syscall::TraceConfig {
        rootdir: args.rootdir,
        binds,
        loader_shim: args.loader_shim,
    };

    match unsafe { fork() }.expect("fork failed") {
        ForkResult::Child => {
            syscall::child_setup();

            let prog_c = CString::new(args.program.clone()).unwrap();
            let mut cargs: Vec<CString> = Vec::with_capacity(args.args.len() + 1);
            cargs.push(prog_c.clone());
            for a in &args.args {
                cargs.push(CString::new(a.as_str()).unwrap());
            }

            execvp(&prog_c, &cargs).expect("exec failed");
        }
        ForkResult::Parent { child } => {
            syscall::trace_loop(child, config);
        }
    }
}
