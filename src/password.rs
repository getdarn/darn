//! Reading a password from the terminal without echoing it.
//!
//! `console::Term::read_secure_line` does the same job, but a Ctrl+C during
//! the read kills the process before it can turn echo back on, leaving the
//! shell unusable — and Ctrl+C is exactly what the password prompt tells the
//! user to press to cancel. So the window where echo is off is guarded by a
//! signal handler that restores the terminal before dying.

use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// `c_lflag` as it was before echo was turned off, for the signal handler to
/// put back. A plain integer because a handler may not lock anything.
static SAVED_LFLAG: AtomicU64 = AtomicU64::new(0);

/// Whether a read is currently in progress with echo off.
static ECHO_DISABLED: AtomicBool = AtomicBool::new(false);

/// Restore echo and then die as if the signal had never been handled, so the
/// shell still sees the usual 130 for an interrupted command.
///
/// Only `tcgetattr`, `tcsetattr`, `signal` and `raise` are called here; all
/// four are async-signal-safe.
extern "C" fn restore_and_die(sig: libc::c_int) {
    if ECHO_DISABLED.swap(false, Ordering::SeqCst) {
        unsafe {
            let mut term: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut term) == 0 {
                term.c_lflag = SAVED_LFLAG.load(Ordering::SeqCst) as libc::tcflag_t;
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &term);
            }
        }
    }
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Print `prompt` and read one line from the terminal without echoing it.
///
/// Errors if stdin is not a terminal: there is nothing to read a password
/// from, and silently reading a piped line would be worse than saying so.
pub fn read_password(prompt: &str) -> io::Result<String> {
    if !stdin_is_terminal() {
        return Err(io::Error::other("stdin is not a terminal"));
    }

    print!("{prompt}");
    io::stdout().flush()?;

    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(libc::STDIN_FILENO, &mut term) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let original_lflag = term.c_lflag;
    SAVED_LFLAG.store(original_lflag as u64, Ordering::SeqCst);

    let (previous_int, previous_term) = unsafe {
        let handler = restore_and_die as *const () as libc::sighandler_t;
        (
            libc::signal(libc::SIGINT, handler),
            libc::signal(libc::SIGTERM, handler),
        )
    };
    ECHO_DISABLED.store(true, Ordering::SeqCst);
    term.c_lflag &= !libc::ECHO;
    let set = unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &term) };

    let read = if set == 0 {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).map(|_| line)
    } else {
        Err(io::Error::last_os_error())
    };

    ECHO_DISABLED.store(false, Ordering::SeqCst);
    term.c_lflag = original_lflag;
    unsafe {
        libc::tcsetattr(libc::STDIN_FILENO, libc::TCSAFLUSH, &term);
        libc::signal(libc::SIGINT, previous_int);
        libc::signal(libc::SIGTERM, previous_term);
    }
    // The Enter that ended the line was not echoed either.
    println!();

    let line = read?;
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

pub fn stdin_is_terminal() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}
