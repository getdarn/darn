use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ssh2::{
    CheckResult, HashType, HostKeyType, KeyboardInteractivePrompt, KnownHostFileKind, Prompt,
    Session,
};

use crate::errors::DarnError;

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(300);

/// The keys tried when none was named, newest algorithm first — the same
/// names, in the same order, as OpenSSH's own defaults.
const DEFAULT_KEY_NAMES: [&str; 4] = ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa"];

#[derive(Clone, Debug)]
pub struct CommandResult {
    #[allow(dead_code)] // mirrors the darn3 CommandResult shape
    pub command: String,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandResult {
    #[allow(dead_code)]
    pub fn ok(&self) -> bool {
        self.exit_code == 0
    }
}

/// Called with (command, stdout, stderr, exit_code) after every executed
/// command; the hostname is captured by the closure.
pub type Recorder<'a> = Box<dyn Fn(&str, &str, &str, i64) + 'a>;

/// One piece of a running command, delivered as it happens.
pub enum OutEvent<'b> {
    /// The full command, about to be executed.
    Command(&'b str),
    Stdout(&'b [u8]),
    Stderr(&'b [u8]),
}

/// Called with each chunk as it arrives, when live output is wanted.
///
/// `Fn` rather than `FnMut`, matching `Recorder`: a sink writes to a shared
/// destination such as the terminal, and needing no `&mut` lets `run` hold it
/// alongside the borrow of the session itself.
pub type OutputSink<'a> = Box<dyn Fn(OutEvent<'_>) + 'a>;

/// SSH session that logs every command via a recorder callback.
///
/// Not thread-safe; create one per worker thread. Authentication never
/// prompts: explicit key file, then the SSH agent, then the default
/// ~/.ssh/id_* keys. Unknown or mismatched host keys are rejected.
/// `connect_with_password` is the one exception, and only `server add` uses
/// it — to put a key on a host that has none.
pub struct SshSession<'a> {
    pub hostname: String,
    user: String,
    recorder: Option<Recorder<'a>>,
    sink: Option<OutputSink<'a>>,
    sess: Session,
    dry_run: bool,
    plan: Vec<String>,
}

/// How a session should authenticate.
enum Auth<'p> {
    /// The usual order: explicit key, then the agent, then ~/.ssh/id_*.
    Keys(Option<&'p str>),
    /// A password typed at the terminal, held only for this connect.
    Password(&'p str),
}

/// A failed connect, split by whether authentication was what failed.
///
/// Only that case means "the host is reachable and its key is known, we just
/// have no credential it accepts" — the one case where offering to install a
/// key is the right response rather than a way to paper over a bad host key.
enum ConnectErr {
    Auth(String),
    /// The host key is in no known_hosts file. A *mismatched* key is `Other`:
    /// first contact is a question, a changed key is an answer.
    UnknownHostKey(String),
    Other(String),
}

impl ConnectErr {
    fn into_darn(self, hostname: &str) -> DarnError {
        match self {
            ConnectErr::Auth(msg) => {
                DarnError::SshAuth(format!("failed to connect to {hostname}: {msg}"))
            }
            ConnectErr::UnknownHostKey(msg) => {
                DarnError::SshHostKeyUnknown(format!("failed to connect to {hostname}: {msg}"))
            }
            ConnectErr::Other(msg) => {
                DarnError::Ssh(format!("failed to connect to {hostname}: {msg}"))
            }
        }
    }
}

impl<'a> SshSession<'a> {
    pub fn connect(
        hostname: &str,
        user: &str,
        port: u16,
        key_path: Option<&str>,
        recorder: Option<Recorder<'a>>,
        connect_timeout: Duration,
    ) -> Result<Self, DarnError> {
        Self::connect_with(
            hostname,
            user,
            port,
            Auth::Keys(key_path),
            recorder,
            connect_timeout,
        )
    }

    /// Connect with a password rather than a key.
    ///
    /// Only `darn server add` uses this, and only to install a public key on
    /// a host that accepts none of ours; every connection after that is
    /// key-authenticated, so the password is asked for once and never stored.
    pub fn connect_with_password(
        hostname: &str,
        user: &str,
        port: u16,
        password: &str,
        recorder: Option<Recorder<'a>>,
        connect_timeout: Duration,
    ) -> Result<Self, DarnError> {
        Self::connect_with(
            hostname,
            user,
            port,
            Auth::Password(password),
            recorder,
            connect_timeout,
        )
    }

    fn connect_with(
        hostname: &str,
        user: &str,
        port: u16,
        auth: Auth<'_>,
        recorder: Option<Recorder<'a>>,
        connect_timeout: Duration,
    ) -> Result<Self, DarnError> {
        let sess = Self::connect_inner(hostname, user, port, auth, connect_timeout)
            .map_err(|e| e.into_darn(hostname))?;
        Ok(SshSession {
            hostname: hostname.to_string(),
            user: user.to_string(),
            recorder,
            sink: None,
            sess,
            dry_run: false,
            plan: Vec::new(),
        })
    }

    /// Attach (or clear) a sink that receives output as the command produces
    /// it, instead of only after it has exited.
    pub fn set_output_sink(&mut self, sink: Option<OutputSink<'a>>) {
        self.sink = sink;
    }

    fn connect_inner(
        hostname: &str,
        user: &str,
        port: u16,
        auth: Auth<'_>,
        connect_timeout: Duration,
    ) -> Result<Session, ConnectErr> {
        let (sess, _addr) =
            Self::open_session(hostname, port, connect_timeout).map_err(ConnectErr::Other)?;
        check_known_hosts(&sess, hostname, port)?;
        match auth {
            Auth::Keys(key_path) => authenticate(&sess, user, key_path),
            Auth::Password(password) => authenticate_password(&sess, user, password),
        }
        .map_err(ConnectErr::Auth)?;

        // From here on, blocking calls are bounded by the command timeout.
        sess.set_timeout(COMMAND_TIMEOUT.as_millis() as u32);
        Ok(sess)
    }

    /// Connect and handshake, without checking the host key or authenticating.
    ///
    /// Returns the address that answered as well as the session: it is what
    /// ssh(1) shows in parentheses when asking about an unknown host, and the
    /// name alone would not say which of several addresses replied.
    fn open_session(
        hostname: &str,
        port: u16,
        connect_timeout: Duration,
    ) -> Result<(Session, SocketAddr), String> {
        let addrs = (hostname, port)
            .to_socket_addrs()
            .map_err(|e| e.to_string())?;
        let mut connected = None;
        let mut last_err = "no addresses resolved".to_string();
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, connect_timeout) {
                Ok(s) => {
                    connected = Some((s, addr));
                    break;
                }
                Err(e) => last_err = e.to_string(),
            }
        }
        let (stream, addr) = connected.ok_or(last_err)?;

        let mut sess = Session::new().map_err(|e| e.to_string())?;
        sess.set_timeout(connect_timeout.as_millis() as u32);
        // Prefer the host key types our known_hosts already stores for this
        // host, as OpenSSH does. Without this, libssh2 may negotiate a key
        // type different from the stored one, and the later comparison would
        // wrongly report a mismatch.
        if let Some(prefs) = preferred_hostkey_algorithms(hostname, port) {
            let _ = sess.method_pref(ssh2::MethodType::HostKey, &prefs);
        }
        sess.set_tcp_stream(stream);
        sess.handshake().map_err(|e| e.to_string())?;
        Ok((sess, addr))
    }

    /// Record commands instead of running them, for `--dry-run`.
    ///
    /// Only affects `run`; `probe` still goes to the host, since knowing what
    /// darn would do to a host means looking at the host first.
    pub fn set_dry_run(&mut self, dry_run: bool) {
        self.dry_run = dry_run;
    }

    /// Take the commands `run` recorded rather than issued, emptying the list.
    pub fn take_plan(&mut self) -> Vec<String> {
        std::mem::take(&mut self.plan)
    }

    /// Run a command that changes the host.
    ///
    /// Under `set_dry_run` the command is recorded into the plan and never
    /// reaches the host: it returns as though it had succeeded silently, so
    /// that the caller walks the same path it would have walked for real and
    /// the rest of the plan is the rest of that path. Nothing is written to
    /// the command log either — nothing ran, and the log is a record of what
    /// did.
    ///
    /// This is the dangerous direction, so it is the one that carries the
    /// plain name: a new call site that has not thought about dry run at all
    /// is protected by default, and the mistake a `probe` misuse makes is
    /// only to omit a command from a plan.
    pub fn run(
        &mut self,
        command: &str,
        sudo: bool,
        check: bool,
    ) -> Result<CommandResult, DarnError> {
        let full_cmd = if sudo {
            self.with_sudo(command)
        } else {
            command.to_string()
        };
        if self.dry_run {
            self.plan.push(full_cmd.clone());
            return Ok(CommandResult {
                command: full_cmd,
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            });
        }
        self.exec(&full_cmd, check)
    }

    /// Run a read-only command, dry run included.
    ///
    /// Probes are how a handler decides what it would do — which package
    /// manager the host has, which units are stale — so a dry run that
    /// skipped them could not report a plan at all.
    pub fn probe(
        &mut self,
        command: &str,
        sudo: bool,
        check: bool,
    ) -> Result<CommandResult, DarnError> {
        let full_cmd = if sudo {
            self.with_sudo(command)
        } else {
            command.to_string()
        };
        self.exec(&full_cmd, check)
    }

    fn exec(&mut self, full_cmd: &str, check: bool) -> Result<CommandResult, DarnError> {
        let full_cmd = full_cmd.to_string();

        let outcome = match &self.sink {
            None => exec_buffered(&self.sess, &full_cmd, None),
            Some(sink) => exec_streamed(&self.sess, &full_cmd, sink.as_ref()),
        };
        let (stdout, stderr, exit_code) =
            outcome.map_err(|e| DarnError::Ssh(format!("command failed to execute: {e}")))?;

        // Both paths accumulate the whole of each stream, so the log a
        // streamed command leaves behind is the same as any other's.
        if let Some(recorder) = &self.recorder {
            recorder(&full_cmd, &stdout, &stderr, exit_code as i64);
        }

        if check && exit_code != 0 {
            // A streamed command has already put its stderr on the terminal;
            // repeating it here would fold a wall of output into a table cell.
            let tail = if self.sink.is_some() {
                String::new()
            } else {
                format!("\n{stderr}")
            };
            return Err(DarnError::Ssh(format!(
                "{}: command exited {exit_code}: {full_cmd}{tail}",
                self.hostname
            )));
        }
        Ok(CommandResult {
            command: full_cmd,
            exit_code,
            stdout,
            stderr,
        })
    }

    /// Run a command with `stdin` written to it, for the one thing that may
    /// not appear in a command string: a password on its way to `sudo -S`.
    ///
    /// No sudo wrapping — the caller builds that, since the point here is a
    /// wrapper `with_sudo` deliberately does not offer. Never streamed
    /// either: a sink puts what it is given on the terminal, and stdin is not
    /// something to echo. What the recorder sees is the command, stdout,
    /// stderr and exit code, exactly as for any other command; `stdin` is not
    /// passed to it and so never reaches the command log.
    pub fn run_with_stdin(
        &mut self,
        command: &str,
        stdin: &str,
        check: bool,
    ) -> Result<CommandResult, DarnError> {
        let (stdout, stderr, exit_code) = exec_buffered(&self.sess, command, Some(stdin))
            .map_err(|e| DarnError::Ssh(format!("command failed to execute: {e}")))?;

        if let Some(recorder) = &self.recorder {
            recorder(command, &stdout, &stderr, exit_code as i64);
        }

        if check && exit_code != 0 {
            return Err(DarnError::Ssh(format!(
                "{}: command exited {exit_code}: {command}\n{stderr}",
                self.hostname
            )));
        }
        Ok(CommandResult {
            command: command.to_string(),
            exit_code,
            stdout,
            stderr,
        })
    }

    fn with_sudo(&self, command: &str) -> String {
        if self.user == "root" {
            return command.to_string();
        }
        format!("sudo -n -- sh -c {}", crate::quote::sh_quote(command))
    }
}

/// Run a command, returning its output once it has exited.
///
/// `stdin`, when given, is written to the command before its input is closed.
fn exec_buffered(
    sess: &Session,
    full_cmd: &str,
    stdin: Option<&str>,
) -> Result<(String, String, i32), String> {
    let mut ch = sess.channel_session().map_err(|e| e.to_string())?;
    ch.exec(full_cmd).map_err(|e| e.to_string())?;
    if let Some(input) = stdin {
        ch.write_all(input.as_bytes()).map_err(|e| e.to_string())?;
        ch.flush().map_err(|e| e.to_string())?;
    }
    let _ = ch.send_eof();
    // libssh2 buffers the stream not currently being read, so full
    // sequential reads cannot deadlock the way raw pipes would.
    let mut out_raw = Vec::new();
    let mut err_raw = Vec::new();
    ch.read_to_end(&mut out_raw).map_err(|e| e.to_string())?;
    ch.stderr()
        .read_to_end(&mut err_raw)
        .map_err(|e| e.to_string())?;
    let _ = ch.close();
    let _ = ch.wait_close();
    let code = ch.exit_status().map_err(|e| e.to_string())?;
    Ok((
        String::from_utf8_lossy(&out_raw).into_owned(),
        String::from_utf8_lossy(&err_raw).into_owned(),
        code,
    ))
}

/// Run a command, handing every chunk to `sink` as it arrives.
///
/// Returns the same triple as `exec_buffered`: the sink is an addition to the
/// captured output, not a replacement for it.
fn exec_streamed(
    sess: &Session,
    full_cmd: &str,
    sink: &dyn Fn(OutEvent<'_>),
) -> Result<(String, String, i32), String> {
    sink(OutEvent::Command(full_cmd));

    let mut ch = sess.channel_session().map_err(|e| e.to_string())?;
    ch.exec(full_cmd).map_err(|e| e.to_string())?;
    let _ = ch.send_eof();

    let mut out_raw = Vec::new();
    let mut err_raw = Vec::new();
    let pumped = pump(sess, &mut ch, sink, &mut out_raw, &mut err_raw);
    // Blocking is a property of the session, which outlives this command, so
    // it has to be restored however the pump ended.
    sess.set_blocking(true);
    pumped?;

    let _ = ch.close();
    let _ = ch.wait_close();
    let code = ch.exit_status().map_err(|e| e.to_string())?;
    Ok((
        String::from_utf8_lossy(&out_raw).into_owned(),
        String::from_utf8_lossy(&err_raw).into_owned(),
        code,
    ))
}

/// Drain both streams until the remote closes the channel.
///
/// Non-blocking, because a blocking read can only wait on one stream at a
/// time and stderr would then surface only once stdout had finished — the
/// opposite of watching a command run. libssh2 ignores its own timeout in
/// this mode, so COMMAND_TIMEOUT is re-imposed here with the meaning it has
/// when blocking: time without progress, not total runtime.
fn pump(
    sess: &Session,
    ch: &mut ssh2::Channel,
    sink: &dyn Fn(OutEvent<'_>),
    out_raw: &mut Vec<u8>,
    err_raw: &mut Vec<u8>,
) -> Result<(), String> {
    const IDLE_POLL: Duration = Duration::from_millis(20);

    let mut stderr = ch.stderr();
    let mut buf = [0u8; 8192];
    let mut last_progress = Instant::now();
    sess.set_blocking(false);

    loop {
        let mut progressed = false;

        match ch.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                out_raw.extend_from_slice(&buf[..n]);
                sink(OutEvent::Stdout(&buf[..n]));
                progressed = true;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.to_string()),
        }
        match stderr.read(&mut buf) {
            Ok(0) => {}
            Ok(n) => {
                err_raw.extend_from_slice(&buf[..n]);
                sink(OutEvent::Stderr(&buf[..n]));
                progressed = true;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.to_string()),
        }

        if progressed {
            last_progress = Instant::now();
            continue;
        }
        // Tested only after a pass that read nothing: libssh2 can report EOF
        // with data still buffered, so draining has to come first.
        if ch.eof() {
            return Ok(());
        }
        if last_progress.elapsed() >= COMMAND_TIMEOUT {
            return Err(format!("no output for {}s", COMMAND_TIMEOUT.as_secs()));
        }
        std::thread::sleep(IDLE_POLL);
    }
}

// Dropping the ssh2 Session sends a disconnect and swallows errors, which is
// what we want: the peer may already be gone — e.g. we just rebooted it.

pub(crate) fn known_hosts_files() -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(home) = dirs::home_dir() {
        files.push(home.join(".ssh").join("known_hosts"));
    }
    files.push(PathBuf::from("/etc/ssh/ssh_known_hosts"));
    files
}

/// Host key algorithms in OpenSSH's own order of preference.
const SUPPORTED_HOSTKEY_ALGORITHMS: [&str; 8] = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ssh-rsa",
    "ssh-dss",
];

/// The host key algorithms to offer, with the types already stored in
/// known_hosts for this host first — mirroring OpenSSH's behaviour so the
/// server presents a key we can actually verify.
fn preferred_hostkey_algorithms(hostname: &str, port: u16) -> Option<String> {
    let mut stored_types: Vec<String> = Vec::new();
    for file in known_hosts_files() {
        let Ok(content) = std::fs::read_to_string(&file) else {
            continue;
        };
        for key_type in stored_key_types(&content, hostname, port) {
            if !stored_types.contains(&key_type) {
                stored_types.push(key_type);
            }
        }
    }
    if stored_types.is_empty() {
        // First contact, so there is no stored type to match. Ask in
        // OpenSSH's order anyway: the key darn then shows and records is the
        // one `ssh` would have shown for the same host, which is what makes
        // comparing the two fingerprints meaningful.
        return Some(SUPPORTED_HOSTKEY_ALGORITHMS.join(","));
    }
    let algs = expand_and_order(&stored_types);
    if algs.is_empty() {
        None
    } else {
        Some(algs)
    }
}

/// Build the negotiation list: the stored key types first (an ssh-rsa key
/// verifies the rsa-sha2-* signature variants too), then the remaining
/// algorithms libssh2 supports as fallbacks, so an unknown host still
/// handshakes and then fails the known-hosts check with a useful message.
fn expand_and_order(stored_types: &[String]) -> String {
    const SUPPORTED: [&str; 8] = SUPPORTED_HOSTKEY_ALGORITHMS;
    let mut algs: Vec<&str> = Vec::new();
    for key_type in stored_types {
        let expanded: &[&str] = match key_type.as_str() {
            "ssh-rsa" => &["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"],
            other => match SUPPORTED.iter().find(|a| **a == other) {
                Some(alg) => std::slice::from_ref(alg),
                None => &[],
            },
        };
        for alg in expanded {
            if !algs.contains(alg) {
                algs.push(alg);
            }
        }
    }
    if algs.is_empty() {
        return String::new();
    }
    for alg in SUPPORTED {
        if !algs.contains(&alg) {
            algs.push(alg);
        }
    }
    algs.join(",")
}

/// Key types of known_hosts entries matching `hostname`/`port`, in file order.
fn stored_key_types(content: &str, hostname: &str, port: u16) -> Vec<String> {
    // A bare hostname entry means port 22; other ports only match the
    // bracketed form, as in OpenSSH.
    let bracketed = format!("[{hostname}]:{port}");
    let mut candidates = vec![bracketed];
    if port == 22 {
        candidates.push(hostname.to_string());
    }
    let mut types = Vec::new();
    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let mut patterns = fields.next().unwrap_or("");
        // Skip marker lines (@cert-authority, @revoked): not plain host keys.
        if patterns.starts_with('@') {
            continue;
        }
        let Some(key_type) = fields.next() else {
            continue;
        };
        if !key_type.starts_with("ssh-") && !key_type.starts_with("ecdsa-") {
            continue; // e.g. legacy "1024 35 ..." RSA1 lines
        }
        if patterns.starts_with("|1|") {
            if candidates.iter().any(|c| hashed_entry_matches(patterns, c)) {
                types.push(key_type.to_string());
            }
            continue;
        }
        // Comma-separated glob patterns; negations exclude the whole line.
        let mut matched = false;
        let mut negated = false;
        loop {
            let (pattern, rest) = match patterns.split_once(',') {
                Some((p, r)) => (p, Some(r)),
                None => (patterns, None),
            };
            let (pattern, negate) = match pattern.strip_prefix('!') {
                Some(p) => (p, true),
                None => (pattern, false),
            };
            if candidates.iter().any(|c| glob_match(pattern, c)) {
                if negate {
                    negated = true;
                } else {
                    matched = true;
                }
            }
            match rest {
                Some(r) => patterns = r,
                None => break,
            }
        }
        if matched && !negated {
            types.push(key_type.to_string());
        }
    }
    types
}

/// Match a hashed `|1|salt|hash` known_hosts pattern: HMAC-SHA1(salt, host).
fn hashed_entry_matches(pattern: &str, hostname: &str) -> bool {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    let mut parts = pattern.splitn(4, '|');
    let (_, magic, salt_b64, hash_b64) = (parts.next(), parts.next(), parts.next(), parts.next());
    if magic != Some("1") {
        return false;
    }
    let engine = base64::engine::general_purpose::STANDARD;
    let (Some(salt), Some(hash)) = (
        salt_b64.and_then(|s| engine.decode(s).ok()),
        hash_b64.and_then(|s| engine.decode(s).ok()),
    ) else {
        return false;
    };
    let Ok(mut mac) = Hmac::<sha1::Sha1>::new_from_slice(&salt) else {
        return false;
    };
    mac.update(hostname.as_bytes());
    mac.verify_slice(&hash).is_ok()
}

/// OpenSSH-style host pattern match: `*` and `?` wildcards, case-insensitive.
pub(crate) fn glob_match(pattern: &str, host: &str) -> bool {
    fn inner(p: &[u8], h: &[u8]) -> bool {
        match (p.first(), h.first()) {
            (None, None) => true,
            (Some(b'*'), _) => inner(&p[1..], h) || (!h.is_empty() && inner(p, &h[1..])),
            (Some(b'?'), Some(_)) => inner(&p[1..], &h[1..]),
            (Some(a), Some(b)) => a.eq_ignore_ascii_case(b) && inner(&p[1..], &h[1..]),
            _ => false,
        }
    }
    inner(pattern.as_bytes(), host.as_bytes())
}

fn check_known_hosts(sess: &Session, hostname: &str, port: u16) -> Result<(), ConnectErr> {
    let mut kh = sess
        .known_hosts()
        .map_err(|e| ConnectErr::Other(e.to_string()))?;
    for file in known_hosts_files() {
        // Missing files are fine; paramiko's load_system_host_keys ignores them too.
        let _ = kh.read_file(&file, KnownHostFileKind::OpenSSH);
    }

    let (key, _key_type) = sess
        .host_key()
        .ok_or_else(|| ConnectErr::Other("server presented no host key".to_string()))?;
    match kh.check_port(hostname, port, key) {
        CheckResult::Match => Ok(()),
        CheckResult::Mismatch => Err(ConnectErr::Other(format!(
            "host key mismatch for '{hostname}' (possible MITM); fix ~/.ssh/known_hosts"
        ))),
        CheckResult::NotFound => Err(ConnectErr::UnknownHostKey(format!(
            "server '{hostname}' not found in known_hosts; connect once with ssh to accept its key"
        ))),
        // Not a first contact: libssh2 could not perform the comparison at
        // all, and offering to record a key would paper over that.
        CheckResult::Failure => Err(ConnectErr::Other(format!(
            "could not check the host key for '{hostname}' against known_hosts"
        ))),
    }
}

fn authenticate(sess: &Session, user: &str, key_path: Option<&str>) -> Result<(), String> {
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
fn authenticate_password(sess: &Session, user: &str, password: &str) -> Result<(), String> {
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

/// A host key as the server presented it, ready to show and to record.
pub struct HostKey {
    /// The address that answered, as ssh(1) prints it in parentheses.
    pub address: String,
    /// `SHA256:...`, the same string `ssh-keygen -lf` shows.
    pub fingerprint: String,
    /// The algorithm as ssh(1) names it in the prompt, e.g. `ED25519`.
    pub algorithm: String,
    /// The algorithm as known_hosts spells it, e.g. `ssh-ed25519`.
    key_type: String,
    key: Vec<u8>,
}

/// Fetch a host's key without authenticating or checking known_hosts.
///
/// Used to show the user what they are being asked to trust. Trusting it is a
/// separate step: whatever is recorded here is verified by the real connect
/// that follows, so a key swapped in between the two fails as a mismatch
/// rather than slipping through.
pub fn probe_host_key(
    hostname: &str,
    port: u16,
    connect_timeout: Duration,
) -> Result<HostKey, DarnError> {
    let (sess, addr) = SshSession::open_session(hostname, port, connect_timeout)
        .map_err(|e| DarnError::Ssh(format!("failed to connect to {hostname}: {e}")))?;

    let (key, key_type) = sess
        .host_key()
        .ok_or_else(|| DarnError::Ssh(format!("{hostname} presented no host key")))?;
    let (algorithm, wire_name) = match key_type {
        HostKeyType::Ed25519 => ("ED25519", "ssh-ed25519"),
        HostKeyType::Rsa => ("RSA", "ssh-rsa"),
        HostKeyType::Dss => ("DSA", "ssh-dss"),
        HostKeyType::Ecdsa256 => ("ECDSA", "ecdsa-sha2-nistp256"),
        HostKeyType::Ecdsa384 => ("ECDSA", "ecdsa-sha2-nistp384"),
        HostKeyType::Ecdsa521 => ("ECDSA", "ecdsa-sha2-nistp521"),
        // Recording a key we cannot name would produce a line no ssh could
        // read back, so stop rather than write nonsense.
        HostKeyType::Unknown => {
            return Err(DarnError::Ssh(format!(
                "{hostname} presented a host key of a type darn cannot record"
            )))
        }
    };

    // libssh2 hashes the key for us, which is why no sha2 crate is needed.
    use base64::Engine;
    let digest = sess
        .host_key_hash(HashType::Sha256)
        .ok_or_else(|| DarnError::Ssh(format!("{hostname} gave no SHA256 host key hash")))?;
    let fingerprint = format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    );

    Ok(HostKey {
        address: addr.ip().to_string(),
        fingerprint,
        algorithm: algorithm.to_string(),
        key_type: wire_name.to_string(),
        key: key.to_vec(),
    })
}

/// Where else this exact key is already trusted, as `file:line: pattern`.
///
/// ssh(1) shows this when asking about an unknown name, and it is the useful
/// half of the question: a key already trusted under another name is a host
/// you have met, not a stranger.
pub fn other_names_for_key(host_key: &HostKey) -> Vec<String> {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(&host_key.key);
    let mut found = Vec::new();
    for file in known_hosts_files() {
        let Ok(content) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (index, raw) in content.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split_whitespace();
            let (Some(patterns), Some(_type), Some(key)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            if key == encoded {
                found.push(format!("{}:{}: {patterns}", file.display(), index + 1));
            }
        }
    }
    found
}

/// Record `host_key` in the user's known_hosts, returning the file written.
///
/// The entry is hashed, as OpenSSH writes them here, and names the host the
/// way `check_port` looks it up: bare at port 22, `[host]:port` otherwise.
pub fn remember_host_key(
    host_key: &HostKey,
    hostname: &str,
    port: u16,
) -> Result<PathBuf, DarnError> {
    let name = if port == 22 {
        hostname.to_string()
    } else {
        format!("[{hostname}]:{port}")
    };
    let mut salt = [0u8; 20];
    getrandom::fill(&mut salt)
        .map_err(|e| DarnError::Other(format!("cannot generate a known_hosts salt: {e}")))?;

    // Only ever the user's own file: /etc/ssh/ssh_known_hosts is the
    // administrator's, and darn is not it.
    let path = dirs::home_dir()
        .ok_or_else(|| DarnError::Other("no home directory to write known_hosts in".to_string()))?
        .join(".ssh")
        .join("known_hosts");
    let entry = known_hosts_entry(&name, host_key, &salt);
    append_known_host(&path, &entry)
        .map_err(|e| DarnError::Other(format!("cannot write {}: {e}", path.display())))?;
    Ok(path)
}

/// One hashed known_hosts line: `|1|<salt>|<HMAC-SHA1(salt, name)> type key`.
fn known_hosts_entry(name: &str, host_key: &HostKey, salt: &[u8]) -> String {
    use base64::Engine;
    use hmac::{Hmac, Mac};

    let engine = base64::engine::general_purpose::STANDARD;
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(salt).expect("HMAC takes a key of any size");
    mac.update(name.as_bytes());
    let hash = mac.finalize().into_bytes();
    format!(
        "|1|{}|{} {} {}",
        engine.encode(salt),
        engine.encode(hash),
        host_key.key_type,
        engine.encode(&host_key.key)
    )
}

/// Append a line, creating ~/.ssh and known_hosts with the modes ssh expects.
///
/// A file not ending in a newline gets one first: appending blindly would
/// otherwise splice our entry onto the end of somebody else's, silently
/// invalidating both.
fn append_known_host(path: &Path, entry: &str) -> std::io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    if let Some(dir) = path.parent() {
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
        }
    }
    // Readable as well as appendable: the trailing-newline check below has
    // to look at what is already there. Appending still lands at the end
    // whatever the read leaves the cursor on.
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .read(true)
        .mode(0o600)
        .open(path)?;

    let end = file.seek(SeekFrom::End(0))?;
    if end > 0 {
        let mut last = [0u8; 1];
        file.seek(SeekFrom::End(-1))?;
        std::io::Read::read_exact(&mut file, &mut last)?;
        if last[0] != b'\n' {
            file.write_all(b"\n")?;
        }
    }
    file.write_all(entry.as_bytes())?;
    file.write_all(b"\n")
}

/// The public key to install on a host that accepts none of ours, following
/// the order `authenticate` tries private keys in. An explicit `--key` names
/// its own `.pub` sibling.
///
/// None when there is nothing to install — no `~/.ssh/id_*.pub` at all, or a
/// named key whose public half is missing.
pub fn default_public_key(key_path: Option<&str>) -> Option<PathBuf> {
    if let Some(key) = key_path {
        let path = expand_tilde(key);
        let public = if path.extension().is_some_and(|ext| ext == "pub") {
            path
        } else {
            let mut name = path.file_name()?.to_os_string();
            name.push(".pub");
            path.with_file_name(name)
        };
        return public.exists().then_some(public);
    }
    let ssh_dir = dirs::home_dir()?.join(".ssh");
    DEFAULT_KEY_NAMES
        .iter()
        .map(|name| ssh_dir.join(format!("{name}.pub")))
        .find(|path| path.exists())
}

/// The remote command that appends `public_key` to the user's
/// authorized_keys, creating ~/.ssh at 700 and the file at 600 if needed.
///
/// Written to be safe to run twice: an identical line already present is left
/// alone. `restorecon` matches what ssh-copy-id does, so the file is usable
/// on an SELinux host; hosts without it skip that step.
pub fn install_authorized_key_command(public_key: &str) -> String {
    let key = crate::quote::sh_quote(public_key);
    format!(
        "umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && \
{{ grep -qxF {key} ~/.ssh/authorized_keys || printf '%s\\n' {key} >> ~/.ssh/authorized_keys; }} && \
{{ command -v restorecon >/dev/null 2>&1 && restorecon -F ~/.ssh ~/.ssh/authorized_keys >/dev/null 2>&1; true; }}"
    )
}

/// Wrap `command` in a sudo that takes its password on stdin.
///
/// The counterpart to `with_sudo`'s `sudo -n`, for the one moment darn has a
/// password to spend: `-S` reads it from stdin rather than a tty, and `-p ''`
/// keeps sudo's prompt out of the stderr we report. The password stays out of
/// the command string, and so out of the command log.
pub fn sudo_password_command(command: &str) -> String {
    format!("sudo -S -p '' -- sh -c {}", crate::quote::sh_quote(command))
}

fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    Path::new(path).to_path_buf()
}

#[cfg(test)]
mod known_hosts_tests {
    use super::*;

    #[test]
    fn plain_entries_match_by_name_and_port() {
        let content = "\
example.com ssh-ed25519 AAAAkey1 comment
other.com ssh-rsa AAAAkey2
[example.com]:2222 ecdsa-sha2-nistp256 AAAAkey3
";
        assert_eq!(
            stored_key_types(content, "example.com", 22),
            ["ssh-ed25519"]
        );
        assert_eq!(
            stored_key_types(content, "example.com", 2222),
            ["ecdsa-sha2-nistp256"]
        );
        assert!(stored_key_types(content, "nowhere.com", 22).is_empty());
    }

    #[test]
    fn comma_lists_globs_and_negations() {
        let content = "\
web-*,!web-03 ssh-ed25519 AAAAkey
?db.example.com ecdsa-sha2-nistp384 AAAAkey
";
        assert_eq!(stored_key_types(content, "web-01", 22), ["ssh-ed25519"]);
        assert!(stored_key_types(content, "web-03", 22).is_empty());
        assert_eq!(
            stored_key_types(content, "adb.example.com", 22),
            ["ecdsa-sha2-nistp384"]
        );
    }

    #[test]
    fn markers_comments_and_legacy_lines_are_skipped() {
        let content = "\
# a comment
@cert-authority example.com ssh-rsa AAAAca
@revoked example.com ssh-ed25519 AAAAbad
example.com 1024 35 1234567890
";
        assert!(stored_key_types(content, "example.com", 22).is_empty());
    }

    #[test]
    fn hashed_entries_match_via_hmac() {
        // Vectors: HMAC-SHA1 with salt 0x00..0x13 over the hostname.
        let content = "\
|1|AAECAwQFBgcICQoLDA0ODxAREhM=|nnUK16ANsXd3hL31YfAkGOluSjU= ssh-ed25519 AAAAkey
|1|AAECAwQFBgcICQoLDA0ODxAREhM=|Wgcx+Fm+LmaWwC7rQ80eIf2uHe0= ssh-rsa AAAAkey2
";
        assert_eq!(
            stored_key_types(content, "example.com", 22),
            ["ssh-ed25519"]
        );
        assert_eq!(stored_key_types(content, "example.com", 2222), ["ssh-rsa"]);
        assert!(stored_key_types(content, "other.com", 22).is_empty());
    }

    #[test]
    fn rsa_expands_to_sha2_signature_variants() {
        // Exercise the expansion logic through a temp known_hosts? The file
        // list is fixed, so test the pure pieces instead.
        let types = stored_key_types("h ssh-rsa AAAAkey\n", "h", 22);
        assert_eq!(types, ["ssh-rsa"]);
        // Expansion itself is covered by preferred order construction below.
        let algs = super::expand_and_order(&types);
        assert!(algs.starts_with("rsa-sha2-512,rsa-sha2-256,ssh-rsa,ssh-ed25519"));
    }

    #[test]
    fn stored_type_leads_the_preference_list() {
        let algs = super::expand_and_order(&["ssh-ed25519".to_string()]);
        assert!(algs.starts_with("ssh-ed25519,"));
        assert!(algs.contains("rsa-sha2-512"));
    }
}

#[cfg(test)]
mod host_key_tests {
    use super::*;

    fn a_host_key() -> HostKey {
        HostKey {
            address: "10.42.42.51".to_string(),
            fingerprint: "SHA256:TsA++yDjGBI6RHajtLzDAcpM5B2FM8vv1KeCENzeTdQ".to_string(),
            algorithm: "ED25519".to_string(),
            key_type: "ssh-ed25519".to_string(),
            key: b"a plausible key blob".to_vec(),
        }
    }

    /// The test that matters: what we write is what our own reader matches.
    /// A salt encoded wrongly would leave darn asking about the same host
    /// forever, and nothing else would notice.
    #[test]
    fn a_written_entry_is_found_again_by_the_parser() {
        let entry = known_hosts_entry("proxmox1", &a_host_key(), &[7u8; 20]);
        assert!(entry.starts_with("|1|"));
        assert_eq!(
            stored_key_types(&entry, "proxmox1", 22),
            ["ssh-ed25519"],
            "hashed entry did not match the host it was written for"
        );
        // And it is not a match for anything else.
        assert!(stored_key_types(&entry, "proxmox2", 22).is_empty());
        assert!(stored_key_types(&entry, "proxmox1", 2222).is_empty());
    }

    #[test]
    fn a_non_default_port_is_named_in_brackets() {
        let key = a_host_key();
        let entry = known_hosts_entry("[proxmox1]:2222", &key, &[9u8; 20]);
        assert_eq!(stored_key_types(&entry, "proxmox1", 2222), ["ssh-ed25519"]);
        assert!(stored_key_types(&entry, "proxmox1", 22).is_empty());
    }

    #[test]
    fn a_new_known_hosts_gets_ssh_s_own_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(".ssh").join("known_hosts");
        append_known_host(&path, "|1|salt|hash ssh-ed25519 AAAA").unwrap();

        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        assert_eq!(mode(&path), 0o600);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "|1|salt|hash ssh-ed25519 AAAA\n"
        );
    }

    /// Appending to a file whose last line has no newline must not splice the
    /// two entries together — that would quietly invalidate both.
    #[test]
    fn an_unterminated_last_line_is_closed_first() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known_hosts");
        std::fs::write(&path, "existing.example.com ssh-rsa AAAAold").unwrap();

        append_known_host(&path, "|1|salt|hash ssh-ed25519 AAAAnew").unwrap();

        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "existing.example.com ssh-rsa AAAAold\n|1|salt|hash ssh-ed25519 AAAAnew\n"
        );
    }

    #[test]
    fn a_key_already_trusted_elsewhere_is_reported_with_its_line() {
        // other_names_for_key reads the real known_hosts paths, so exercise
        // the line-matching it depends on rather than the file list.
        let key = a_host_key();
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(&key.key);
        let entry = known_hosts_entry("proxmox1", &key, &[3u8; 20]);
        assert!(
            entry.ends_with(&encoded),
            "the recorded line must carry the key verbatim for lookup to work"
        );
    }
}

#[cfg(test)]
mod key_install_tests {
    use super::*;

    #[test]
    fn the_key_is_quoted_and_written_once() {
        let cmd = install_authorized_key_command("ssh-ed25519 AAAAC3Nz martin@laptop");
        // Quoted, so a comment containing spaces cannot split the command.
        assert!(cmd.contains(
            "printf '%s\\n' 'ssh-ed25519 AAAAC3Nz martin@laptop' >> ~/.ssh/authorized_keys"
        ));
        // Appended only when not already there, so re-adding a host is a no-op.
        assert!(cmd
            .contains("grep -qxF 'ssh-ed25519 AAAAC3Nz martin@laptop' ~/.ssh/authorized_keys ||"));
        // The directory and file exist with private permissions first.
        assert!(cmd.starts_with("umask 077; mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys &&"));
    }

    /// Run the command the way the remote shell will, against a throwaway
    /// HOME. Nothing else executes this string locally, so a syntax slip or a
    /// wrong mode would otherwise only show up on someone's server.
    #[test]
    fn the_command_writes_a_private_authorized_keys_and_repeats_cleanly() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let home = tempfile::tempdir().unwrap();
        let key = "ssh-ed25519 AAAAC3Nz martin@laptop";
        let cmd = install_authorized_key_command(key);

        // Twice: adding a host again must not pile up duplicate lines.
        for run in 1..=2 {
            let status = Command::new("sh")
                .arg("-c")
                .arg(&cmd)
                .env("HOME", home.path())
                .status()
                .unwrap();
            assert!(status.success(), "run {run} of the install command failed");
        }

        let ssh_dir = home.path().join(".ssh");
        let authorized = ssh_dir.join("authorized_keys");
        assert_eq!(
            std::fs::read_to_string(&authorized).unwrap(),
            format!("{key}\n")
        );
        let mode =
            |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        // sshd ignores an authorized_keys file that others can read.
        assert_eq!(mode(&ssh_dir), 0o700);
        assert_eq!(mode(&authorized), 0o600);
    }

    #[test]
    fn keys_already_on_the_host_are_kept() {
        use std::process::Command;

        let home = tempfile::tempdir().unwrap();
        let ssh_dir = home.path().join(".ssh");
        std::fs::create_dir(&ssh_dir).unwrap();
        let authorized = ssh_dir.join("authorized_keys");
        std::fs::write(&authorized, "ssh-rsa AAAAsomeoneelse colleague@laptop\n").unwrap();

        let status = Command::new("sh")
            .arg("-c")
            .arg(install_authorized_key_command(
                "ssh-ed25519 AAAAmine martin@laptop",
            ))
            .env("HOME", home.path())
            .status()
            .unwrap();
        assert!(status.success());

        assert_eq!(
            std::fs::read_to_string(&authorized).unwrap(),
            "ssh-rsa AAAAsomeoneelse colleague@laptop\nssh-ed25519 AAAAmine martin@laptop\n"
        );
    }

    #[test]
    fn an_explicit_key_names_its_public_half() {
        let dir = tempfile::tempdir().unwrap();
        let private = dir.path().join("deploy_key");
        std::fs::write(&private, "private").unwrap();

        // No .pub beside it: nothing to install, and no guessing.
        assert_eq!(default_public_key(Some(private.to_str().unwrap())), None);

        let public = dir.path().join("deploy_key.pub");
        std::fs::write(&public, "ssh-ed25519 AAAA").unwrap();
        assert_eq!(
            default_public_key(Some(private.to_str().unwrap())),
            Some(public.clone())
        );
        // Naming the public half directly works too.
        assert_eq!(
            default_public_key(Some(public.to_str().unwrap())),
            Some(public)
        );
    }
}

#[cfg(test)]
mod quoting_parity_tests {
    // One-off parity check against Python shlex.quote output; reads the
    // fixture produced in the scratchpad. Skipped when the file is absent.
    #[test]
    fn sudo_quoting_matches_python() {
        let path = std::env::var("DARN_PY_QUOTED").unwrap_or_default();
        if path.is_empty() {
            return;
        }
        let expected = std::fs::read_to_string(path).unwrap();
        let apt = crate::hosts::apt::reboot_probe();
        let rh = crate::hosts::redhat::reboot_probe();
        let cmds = [
            apt.to_string(),
            rh.replace("{pm}", "dnf"),
            rh.replace("{pm}", "yum"),
            "systemctl restart 'cron.service' 'postfix@-.service'".to_string(),
            "DEBIAN_FRONTEND=noninteractive apt-get update -qq".to_string(),
        ];
        let mut actual = String::new();
        for cmd in &cmds {
            let quoted = crate::quote::sh_quote(cmd);
            actual.push_str(&format!("sudo -n -- sh -c {quoted}\n=====\n"));
        }
        if let Ok(dump) = std::env::var("DARN_DUMP") {
            std::fs::write(dump, &actual).unwrap();
        }
        assert_eq!(expected, actual);
    }
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// One chunk the sink was handed: when it arrived, which stream it came
    /// from ("cmd"/"out"/"err"), and its text.
    type Chunk = (f32, &'static str, String);

    /// Exercise the streaming read loop against a real host, the way the
    /// known-hosts parity test uses a fixture: skipped unless DARN_STREAM_HOST
    /// names one. Nothing is installed or changed — the probe only echoes and
    /// sleeps — but it needs a server, which is why it cannot run unattended.
    ///
    ///     DARN_STREAM_HOST=myhost cargo test streaming -- --nocapture
    #[test]
    fn output_arrives_while_the_command_is_still_running() {
        let host = std::env::var("DARN_STREAM_HOST").unwrap_or_default();
        if host.is_empty() {
            return;
        }
        let user = std::env::var("DARN_STREAM_USER")
            .or_else(|_| std::env::var("USER"))
            .unwrap();

        let start = Instant::now();
        let mut sess = SshSession::connect(&host, &user, 22, None, None, DEFAULT_CONNECT_TIMEOUT)
            .expect("connect");

        // (elapsed, which stream, text) for every chunk the sink is handed.
        // Shared rather than borrowed, so the sink can be detached and the
        // record read while the session is still alive.
        let seen: Rc<RefCell<Vec<Chunk>>> = Rc::default();
        let recorded = Rc::clone(&seen);
        sess.set_output_sink(Some(Box::new(move |event| {
            let (kind, bytes): (&'static str, &[u8]) = match event {
                OutEvent::Command(c) => ("cmd", c.as_bytes()),
                OutEvent::Stdout(b) => ("out", b),
                OutEvent::Stderr(b) => ("err", b),
            };
            recorded.borrow_mut().push((
                start.elapsed().as_secs_f32(),
                kind,
                String::from_utf8_lossy(bytes).into_owned(),
            ));
        })));

        let res = sess
            .run(
                "for i in 1 2 3; do echo \"out $i\"; echo \"err $i\" >&2; sleep 1; done; exit 7",
                false,
                false,
            )
            .expect("run");

        let seen = seen.borrow().clone();
        for (at, kind, text) in &seen {
            println!("[{at:>6.2}s] {kind} {text:?}");
        }

        // The captured output is unchanged by streaming: darn log still works.
        assert_eq!(res.stdout, "out 1\nout 2\nout 3\n");
        assert_eq!(res.stderr, "err 1\nerr 2\nerr 3\n");
        assert_eq!(res.exit_code, 7);

        // The point of the exercise: it was delivered as it happened, not in
        // one lump at the end. The command sleeps 1s per iteration, so the
        // first chunk must land well before the last.
        let first = seen.iter().find(|(_, k, _)| *k != "cmd").expect("a chunk");
        let last = seen.last().expect("a chunk");
        assert!(
            last.0 - first.0 > 1.5,
            "chunks arrived together, not live: {first:?} .. {last:?}"
        );
        // stderr is not stuck behind stdout finishing.
        assert!(
            seen.iter().any(|(_, k, _)| *k == "err")
                && seen.iter().position(|(_, k, _)| *k == "err").unwrap()
                    < seen.iter().rposition(|(_, k, _)| *k == "out").unwrap(),
            "stderr only appeared after stdout was done: {seen:?}"
        );

        // Blocking mode must have been restored, or the next command breaks.
        let again = sess.run("echo second", false, true).expect("second run");
        assert_eq!(again.stdout, "second\n");

        // A quiet stretch is not EOF. Getting this wrong would silently
        // truncate any upgrade with a long unchatty step in the middle.
        let quiet = sess
            .run("echo before; sleep 20; echo after", false, true)
            .expect("quiet run");
        assert_eq!(quiet.stdout, "before\nafter\n");

        // And detaching the sink returns the session to the buffered path.
        sess.set_output_sink(None);
        let buffered = sess.run("echo third", false, true).expect("third run");
        assert_eq!(buffered.stdout, "third\n");
    }
}
