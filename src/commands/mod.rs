pub mod batch;
pub mod completions;
pub mod log;
pub mod man;
pub mod reboot;
pub mod restartservices;
pub mod server;
pub mod shell;
pub mod status;
pub mod update;
pub mod upgrade;

use std::io::Write;

pub fn session_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Ask a yes/no question defaulting to no, like click.confirm.
pub fn confirm(prompt: &str) -> bool {
    print!("{prompt} [y/N]: ");
    let _ = std::io::stdout().flush();
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_lowercase().as_str(), "y" | "yes")
}
