//! Channel I/O: running one command over an open session, buffered or
//! streamed chunk-by-chunk to a sink.

use std::io::{ErrorKind, Read, Write};
use std::time::{Duration, Instant};

use ssh2::Session;

use super::{OutEvent, COMMAND_TIMEOUT};

/// Run a command, returning its output once it has exited.
///
/// `stdin`, when given, is written to the command before its input is closed.
pub(super) fn exec_buffered(
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
pub(super) fn exec_streamed(
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

#[cfg(test)]
mod streaming_tests {
    use super::super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::time::Instant;

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
