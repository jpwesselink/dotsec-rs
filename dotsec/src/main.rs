#[cfg(feature = "cli")]
use crate::cli::parse_args;
use colored::Colorize;

mod cli;
mod default_options;

/// Lower the soft `RLIMIT_CORE` to 0 so a panic (with `panic = "abort"` in
/// release) can't drop a coredump containing in-flight secret material —
/// DEKs, decrypted plaintext, age private key bytes that `Zeroizing` didn't
/// get to wipe because destructors don't run on abort.
///
/// Only the soft limit is changed; the current hard limit is read first and
/// kept. rlimits are inherited across fork/exec, so lowering the hard limit
/// would permanently forbid core dumps for every child of `dotsec run` (the
/// user's app). Children still inherit a soft limit of 0, but can raise it
/// again up to the untouched hard limit.
///
/// Failure is non-fatal — at worst we're no worse off than before this call
/// existed.
#[cfg(unix)]
fn disable_coredumps() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit/setrlimit take a pointer to a fully-initialized
    // rlimit struct of integer fields; we pass a stack-allocated value.
    // Failure returns -1 and sets errno; we ignore both (if getrlimit fails
    // we don't know the hard limit, so we leave everything alone).
    unsafe {
        if libc::getrlimit(libc::RLIMIT_CORE, &mut limit) != 0 {
            return;
        }
        limit.rlim_cur = 0;
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
}

/// No-op on Windows.
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

#[cfg(all(test, unix))]
mod tests {
    use super::disable_coredumps;

    fn core_limit() -> libc::rlimit {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: valid pointer to a stack-allocated rlimit.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) };
        assert_eq!(rc, 0, "getrlimit(RLIMIT_CORE) failed");
        limit
    }

    /// Runs in-process: lowering the test binary's own soft core limit is
    /// harmless, and the hard limit must come out unchanged anyway.
    #[test]
    fn disable_coredumps_lowers_soft_limit_only() {
        let before = core_limit();
        disable_coredumps();
        let after = core_limit();
        assert_eq!(after.rlim_cur, 0, "soft limit must be 0");
        assert_eq!(
            after.rlim_max, before.rlim_max,
            "hard limit must be left unchanged"
        );
    }
}
