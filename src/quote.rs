/// Return a shell-escaped version of the string, exactly as Python's
/// `shlex.quote` does: single-quote wrapping with `'"'"'` escapes.
///
/// The remote command strings are recorded in the command log, so this must
/// stay byte-identical to what darn3 produced for the same command.
pub fn sh_quote(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }
    let safe = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&b));
    if safe {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_and_safe_strings() {
        assert_eq!(sh_quote(""), "''");
        assert_eq!(sh_quote("cron.service"), "cron.service");
        assert_eq!(sh_quote("a-b_c.d/e:f,g=h@i%j+k"), "a-b_c.d/e:f,g=h@i%j+k");
    }

    #[test]
    fn unsafe_strings_are_single_quoted() {
        assert_eq!(sh_quote("a b"), "'a b'");
        assert_eq!(sh_quote("$HOME"), "'$HOME'");
        assert_eq!(sh_quote("postfix@-.service;x"), "'postfix@-.service;x'");
    }

    #[test]
    fn embedded_single_quotes_use_python_style() {
        // Python: shlex.quote("echo 'hi'") == '\'echo \'"\'"\'hi\'"\'"\'\''
        assert_eq!(sh_quote("echo 'hi'"), "'echo '\"'\"'hi'\"'\"''");
    }

    #[test]
    fn non_ascii_is_quoted() {
        assert_eq!(sh_quote("naïve"), "'naïve'");
    }
}
