use rusqlite::{Connection, Result};
const DB_NAME: &str = "e2ee-file-sharing.db";

pub fn init_db() -> Result<()> {
    let conn = Connection::open(DB_NAME)?;
    let sql = "
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        key_hash BLOB NOT NULL,
        pk_pub BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER NOT NULL,
        user_id INTEGER NOT NULL REFERENCES users(id),
        encrypted_key BLOB NOT NULL,
        PRIMARY KEY (id, user_id)
    );
    CREATE TABLE IF NOT EXISTS files (
        group_id INTEGER NOT NULL REFERENCES groups(id),
        file_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        path TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS group_names (
        group_id INTEGER NOT NULL REFERENCES groups(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        group_name TEXT NOT NULL,
        PRIMARY KEY (group_id, user_id)
    );";
    conn.execute_batch(sql)
}
