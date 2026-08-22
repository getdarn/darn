use clap_complete::env::Shells;

use crate::errors::DarnError;

/// Print the shell code that wires this binary up as its own completer.
///
/// The script calls back into darn on every tab-press, which is what lets
/// hostnames complete; it is the same script `COMPLETE=<shell> darn` emits.
pub fn run(shell: &str) -> Result<i32, DarnError> {
    let shells = Shells::builtins();
    let completer = shells.completer(shell).ok_or_else(|| {
        let known: Vec<&str> = shells.names().collect();
        DarnError::Usage(format!(
            "unknown shell '{shell}'; expected one of {}",
            known.join(", ")
        ))
    })?;

    // An absolute path keeps the script working when darn is not on PATH,
    // which is how it is usually run straight out of target/release.
    let binary = std::env::current_exe()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "darn".to_string());

    completer
        .write_registration("COMPLETE", "darn", "darn", &binary, &mut std::io::stdout())
        .map_err(|e| DarnError::Other(format!("cannot write completion script: {e}")))?;
    Ok(0)
}
