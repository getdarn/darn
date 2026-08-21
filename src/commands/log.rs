use std::path::Path;

use crate::db;
use crate::errors::DarnError;
use crate::render::render_log;

pub fn run(db_path: Option<&Path>, hostname: &str) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;
    if db::get_server(&conn, hostname)?.is_none() {
        return Err(DarnError::Other(format!("no such server: {hostname}")));
    }
    let commands = db::get_last_session_commands(&conn, hostname)?;
    render_log(hostname, &commands);
    Ok(0)
}
