//! The SSH layer: a per-host session that runs commands, records them, and
//! optionally streams their output. The submodules hold what surrounds a
//! session — channel I/O, known_hosts reading, authentication, host-key
//! trust, and key/sudo command strings.

mod auth;
mod channel;
mod keys;
mod known_hosts;
mod trust;

pub use keys::{default_public_key, install_authorized_key_command, sudo_password_command};
pub(crate) use known_hosts::{glob_match, known_hosts_files};
pub use trust::{other_names_for_key, probe_host_key, remember_host_key};

use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use ssh2::Session;

use crate::errors::DarnError;

use auth::{authenticate, authenticate_password};
use channel::{exec_buffered, exec_streamed};
use known_hosts::{check_known_hosts, preferred_hostkey_algorithms};

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

// Dropping the ssh2 Session sends a disconnect and swallows errors, which is
// what we want: the peer may already be gone — e.g. we just rebooted it.
