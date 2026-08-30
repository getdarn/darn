//! Authentication: keys and agent in paramiko's order, or a password typed
//! at the terminal — including the keyboard-interactive form of the same.

use std::path::{Path, PathBuf};

use ssh2::{KeyboardInteractivePrompt, Prompt, Session};

use super::DEFAULT_KEY_NAMES;

pub(super) fn authenticate(
    sess: &Session,
    user: &str,
    key_path: Option<&str>,
) -> Result<(), String> {
    // Explicit key first, then the agent, then the default keys — paramiko's order.
    if let Some(key) = key_path {
        let path = expand_tilde(key);
        sess.userauth_pubkey_file(user, None, &path, None)
            .map_err(|e| format!("authentication with key {key} failed: {e}"))?;
        if sess.authenticated() {
            return Ok(());
        }
    }

    if let Ok(mut agent) = sess.agent() {
        if agent.connect().is_ok() && agent.list_identities().is_ok() {
            if let Ok(identities) = agent.identities() {
                for identity in identities {
                    if agent.userauth(user, &identity).is_ok() && sess.authenticated() {
                        return Ok(());
                    }
                }
            }
        }
    }

    if let Some(home) = dirs::home_dir() {
        for name in DEFAULT_KEY_NAMES {
            let path = home.join(".ssh").join(name);
            if path.exists()
                && sess.userauth_pubkey_file(user, None, &path, None).is_ok()
                && sess.authenticated()
            {
                return Ok(());
            }
        }
    }

    if sess.authenticated() {
        Ok(())
    } else {
        Err("Authentication failed.".to_string())
    }
}

/// Authenticate with a password, however this server asks for one.
///
/// `password` covers the plain method; `keyboard-interactive` is the same
/// password behind PAM, which is all some hosts offer, so both are tried.
pub(super) fn authenticate_password(
    sess: &Session,
    user: &str,
    password: &str,
) -> Result<(), String> {
    // An empty list means the server would not say; try both rather than
    // deciding on its behalf.
    let methods = sess.auth_methods(user).unwrap_or_default().to_string();
    let offers = |method: &str| methods.is_empty() || methods.split(',').any(|m| m == method);

    if offers("password") && sess.userauth_password(user, password).is_ok() && sess.authenticated()
    {
        return Ok(());
    }
    if offers("keyboard-interactive") {
        let mut prompter = PasswordPrompter {
            password,
            answered: false,
        };
        if sess
            .userauth_keyboard_interactive(user, &mut prompter)
            .is_ok()
            && sess.authenticated()
        {
            return Ok(());
        }
    }

    if sess.authenticated() {
        Ok(())
    } else if methods.is_empty() {
        Err("password authentication failed".to_string())
    } else {
        Err(format!(
            "password authentication failed (server offers: {methods})"
        ))
    }
}

/// Answers a PAM-style challenge with the one password we collected.
///
/// The first hidden prompt gets it; anything further — a second factor, say —
/// gets an empty answer and is refused by the server, which is the honest
/// outcome when we have nothing else to give it.
struct PasswordPrompter<'p> {
    password: &'p str,
    answered: bool,
}

impl KeyboardInteractivePrompt for PasswordPrompter<'_> {
    fn prompt<'a>(
        &mut self,
        _user: &str,
        _instructions: &str,
        prompts: &[Prompt<'a>],
    ) -> Vec<String> {
        prompts
            .iter()
            .map(|prompt| {
                if prompt.echo || self.answered {
                    String::new()
                } else {
                    self.answered = true;
                    self.password.to_string()
                }
            })
            .collect()
    }
}

pub(super) fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    Path::new(path).to_path_buf()
}
