use crate::errors::DarnError;

const HINT: &str = "[USER@]HOSTNAME[:PORT]";

/// Split `[user@]hostname[:port]` into user, hostname and optional port.
///
/// The hostname may be a bracketed IPv6 literal (`[::1]:2222`); a bare IPv6
/// literal is only usable without a port, since its colons are ambiguous.
pub fn parse_target(target: &str) -> Result<(String, String, Option<u16>), DarnError> {
    let (ssh_user, rest) = match target.split_once('@') {
        Some((user, rest)) => {
            if user.is_empty() {
                return Err(usage(format!("expected {HINT}")));
            }
            (user.to_string(), rest)
        }
        None => (current_user(), target),
    };

    let mut port: Option<u16> = None;
    let hostname: &str;
    if let Some(after_bracket) = rest.strip_prefix('[') {
        let Some((host, tail)) = after_bracket.split_once(']') else {
            return Err(usage("unterminated [ in address".to_string()));
        };
        hostname = host;
        if let Some(raw_port) = tail.strip_prefix(':') {
            port = Some(parse_port(raw_port)?);
        } else if !tail.is_empty() {
            return Err(usage(format!("expected {HINT}")));
        }
    } else if rest.matches(':').count() == 1 {
        let (host, raw_port) = rest.split_once(':').unwrap();
        hostname = host;
        port = Some(parse_port(raw_port)?);
    } else {
        hostname = rest;
    }

    if hostname.is_empty() {
        return Err(usage(format!("expected {HINT}")));
    }
    Ok((ssh_user, hostname.to_string(), port))
}

fn parse_port(raw: &str) -> Result<u16, DarnError> {
    let port: i64 = raw
        .parse()
        .map_err(|_| usage(format!("port must be a number, got '{raw}'")))?;
    if !(1..=65535).contains(&port) {
        return Err(usage(format!("port out of range: {port}")));
    }
    Ok(port as u16)
}

fn usage(msg: String) -> DarnError {
    DarnError::Usage(msg)
}

pub fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "root".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(target: &str) -> (String, String, Option<u16>) {
        parse_target(target).unwrap()
    }

    #[test]
    fn plain_hostname_uses_current_user_and_no_port() {
        let (user, host, port) = parse("web-01");
        assert_eq!(user, current_user());
        assert_eq!(host, "web-01");
        assert_eq!(port, None);
    }

    #[test]
    fn user_and_port_are_split() {
        let (user, host, port) = parse("admin@web-01:2222");
        assert_eq!(user, "admin");
        assert_eq!(host, "web-01");
        assert_eq!(port, Some(2222));
    }

    #[test]
    fn bracketed_ipv6_with_port() {
        let (_, host, port) = parse("root@[::1]:2222");
        assert_eq!(host, "::1");
        assert_eq!(port, Some(2222));
    }

    #[test]
    fn bracketed_ipv6_without_port() {
        let (_, host, port) = parse("[2001:db8::1]");
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, None);
    }

    #[test]
    fn bare_ipv6_is_a_hostname_with_no_port() {
        // Two or more colons cannot be a host:port split.
        let (_, host, port) = parse("2001:db8::1");
        assert_eq!(host, "2001:db8::1");
        assert_eq!(port, None);
    }

    #[test]
    fn empty_user_is_rejected() {
        assert!(parse_target("@host").is_err());
    }

    #[test]
    fn empty_hostname_is_rejected() {
        assert!(parse_target("").is_err());
        assert!(parse_target("user@").is_err());
        assert!(parse_target(":22").is_err());
    }

    #[test]
    fn unterminated_bracket_is_rejected() {
        let err = parse_target("[::1").unwrap_err();
        assert!(err.to_string().contains("unterminated"));
    }

    #[test]
    fn bracket_with_trailing_junk_is_rejected() {
        assert!(parse_target("[::1]junk").is_err());
    }

    #[test]
    fn bad_ports_are_rejected() {
        assert!(parse_target("host:abc").unwrap_err().to_string().contains("number"));
        assert!(parse_target("host:0").unwrap_err().to_string().contains("range"));
        assert!(parse_target("host:65536").unwrap_err().to_string().contains("range"));
    }
}
