use std::path::Path;

use crate::commands::batch::require_server;
use crate::db;
use crate::errors::DarnError;
use crate::render::render_log;

pub fn run(db_path: Option<&Path>, hostname: &str) -> Result<i32, DarnError> {
    let conn = db::open_db(db_path)?;
    let server = require_server(&conn, hostname)?;
    let commands = db::get_last_session_commands(&conn, hostname)?;
    render_log(&server, &commands);
    Ok(0)
}
