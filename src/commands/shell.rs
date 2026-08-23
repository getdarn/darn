use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;

use crate::db::{self, Server};
use crate::errors::DarnError;

/// The ssh(1) arguments for a managed server.
///
/// `-l user` rather than `user@hostname`, so an IPv6 literal hostname cannot be
/// mis-split, and a `--` before the hostname so a name beginning with a dash is
/// never read as an option. Nothing else is passed: no `-o` overrides, so the
/// user's own ~/.ssh/config still applies.
fn ssh_args(server: &Server) -> Vec<String> {
    let mut args = vec![
        "-l".to_string(),
        server.ssh_user.clone(),
        "-p".to_string(),
        server.ssh_port.to_string(),
    ];
    if let Some(key_path) = &server.ssh_key_path {
        args.push("-i".to_string());
        args.push(key_path.clone());
    }
    args.push("--".to_string());
    args.push(server.hostname.clone());
    args
}

/// Hand the terminal to ssh(1) for an interactive session on a managed host.
///
/// Delegating rather than driving a PTY through libssh2 is deliberate: the user
/// gets raw-mode handling, window resizing, escape sequences, ~/.ssh/config and
/// passphrase prompts from ssh itself, none of which darn's own non-interactive
/// SSH layer offers. Nothing is recorded in the command log — an interactive
/// session has no discrete commands to store.
pub fn run(db_path: Option<&Path>, hostname: &str) -> Result<i32, DarnError> {
    // Scoped so the database connection is closed before ssh takes the
    // terminal, rather than being held open for the length of the session.
    let server = {
        let conn = db::open_db(db_path)?;
        db::get_server(&conn, hostname)?
            .ok_or_else(|| DarnError::Other(format!("no such server: {hostname}")))?
    };

    let status = Command::new("ssh")
        .args(ssh_args(&server))
        .status()
        .map_err(|e| {
            if e.kind() == ErrorKind::NotFound {
                DarnError::Other("ssh not found on PATH: darn shell runs ssh(1)".to_string())
            } else {
                DarnError::Ssh(format!("failed to run ssh: {e}"))
            }
        })?;

    // A signalled ssh reports no code; 255 is ssh's own "it went wrong" status.
    Ok(status.code().unwrap_or(255))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(key_path: Option<&str>) -> Server {
        Server {
            hostname: "web-01".to_string(),
            ssh_user: "admin".to_string(),
            ssh_port: 2222,
            ssh_key_path: key_path.map(str::to_string),
            host_type: "apt".to_string(),
            distribution: None,
            last_update_at: None,
            last_update_ok: None,
            reboot_required: None,
            reboot_detail: None,
            no_all: false,
        }
    }

    #[test]
    fn user_and_port_come_from_the_stored_server() {
        assert_eq!(
            ssh_args(&server(None)),
            ["-l", "admin", "-p", "2222", "--", "web-01"]
        );
    }

    #[test]
    fn a_stored_key_is_passed_with_dash_i() {
        assert_eq!(
            ssh_args(&server(Some("/home/admin/.ssh/id_ed25519"))),
            [
                "-l",
                "admin",
                "-p",
                "2222",
                "-i",
                "/home/admin/.ssh/id_ed25519",
                "--",
                "web-01",
            ]
        );
    }

    #[test]
    fn the_hostname_is_always_last_and_after_the_terminator() {
        for key_path in [None, Some("/key")] {
            let args = ssh_args(&server(key_path));
            assert_eq!(args[args.len() - 2], "--");
            assert_eq!(args[args.len() - 1], "web-01");
        }
    }
}
