use crate::errors::DarnError;
use crate::hosts::ALL_HANDLERS;
use crate::ssh::SshSession;

/// Try each handler's `matches` probe in order, swallowing per-handler errors.
pub fn detect_type(session: &mut SshSession<'_>) -> Result<&'static str, DarnError> {
    let hostname = session.hostname.clone();
    for handler in ALL_HANDLERS {
        if let Ok(true) = handler.matches(session) {
            return Ok(handler.type_name());
        }
    }
    Err(DarnError::Other(format!(
        "could not auto-detect host type for {hostname}; \
expected apt-based (Debian/Ubuntu), RedHat-family, or Mikrotik"
    )))
}
