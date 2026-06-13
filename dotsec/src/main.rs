#[cfg(feature = "cli")]
use crate::cli::parse_args;
use colored::Colorize;

mod cli;
mod default_options;

/// Set `RLIMIT_CORE` to 0 so a panic (with `panic = "abort"` in release)
/// can't drop a coredump containing in-flight secret material — DEKs,
/// decrypted plaintext, age private key bytes that `Zeroizing` didn't
/// get to wipe because destructors don't run on abort.
///
/// `setrlimit` only lowers the soft limit; the hard limit can already be
/// 0 on hardened systems, in which case this is a no-op. Failure is
/// non-fatal — at worst we're no worse off than before this call existed.
#[cfg(unix)]
fn disable_coredumps() {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: libc::setrlimit takes a pointer to a fully-initialized rlimit
    // struct of integer fields. We pass a stack-allocated value with both
    // members set. Failure returns -1 and sets errno; we ignore both.
    unsafe {
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }
}

#[cfg(not(unix))]
fn disable_coredumps() {
    // Windows doesn't have RLIMIT_CORE; Werfault / WER handles crash dumps
    // via registry policy that a user-space process can't toggle. Nothing
    // to do here, but keep the symbol so the call site stays portable.
}

#[tokio::main]
async fn main() {
    disable_coredumps();
    env_logger::init();

    match parse_args().await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);

            let mut source = e.source();
            while let Some(cause) = source {
                eprintln!("  {} {}", "caused by:".red(), cause);
                source = cause.source();
            }

            std::process::exit(1);
        }
    }
}
