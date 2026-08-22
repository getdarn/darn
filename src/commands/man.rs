use std::io::Write;

use crate::errors::DarnError;

/// Print the roff man page for the whole command tree to stdout.
///
/// Hidden from `--help`: it exists so packaging can generate darn.1 at build
/// time without a checked-in copy drifting from the actual arguments.
pub fn run(cmd: clap::Command) -> Result<i32, DarnError> {
    let mut page = Vec::new();
    clap_mangen::Man::new(cmd)
        .render(&mut page)
        .map_err(|e| DarnError::Other(format!("cannot render man page: {e}")))?;
    std::io::stdout()
        .write_all(&page)
        .map_err(|e| DarnError::Other(format!("cannot write man page: {e}")))?;
    Ok(0)
}
