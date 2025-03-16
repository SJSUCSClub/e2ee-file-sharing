use rusqlite::{Connection, Result};

/// initialize all expected tables within a database connection
///
/// has no side effects if these tables already exist
///
/// NOTE: will not update an existing table, so in the case of a migration
/// simply changing the schema within this function will not migrate existing tables
pub fn init_db(conn: &Connection) -> Result<()> {
    let sql = "
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        key_hash BLOB NOT NULL,
        pk_pub BLOB NOT NULL
    );
    CREATE TABLE IF NOT EXISTS groups (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT
    ); 
    CREATE TABLE IF NOT EXISTS groups_user_junction (
        group_id INTEGER NOT NULL REFERENCES groups(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        name TEXT NOT NULL,
        encrypted_key BLOB NOT NULL,
        PRIMARY KEY (group_id, user_id)
    );
    CREATE TABLE IF NOT EXISTS files (
        group_id INTEGER NOT NULL REFERENCES groups(id),
        file_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        filename TEXT NOT NULL,
        path TEXT NOT NULL
    );";
    conn.execute_batch(sql)
}

pub fn get_files_for_user_id(
    conn: &Connection,
    user_id: i32,
) -> Result<Vec<(String, i32, String, i32)>> {
    let query = "
        SELECT f.filename, f.file_id, guj.name, guj.group_id
        From files f
        JOIN groups_user_junction guj on f.group_id = guj.group_id
        WHERE guj.user_id = ?;
    ";

    let mut statement = conn.prepare(query).expect("unable to prepare query");

    statement
        .query_map([user_id], |row| {
            Ok((
                row.get::<usize, String>(0)?,
                row.get::<usize, i32>(1)?,
                row.get::<usize, String>(2)?,
                row.get::<usize, i32>(3)?,
            ))
        })?
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn setup_test_db(conn: &Connection) {
        init_db(&conn).unwrap();

        // create fake records
        conn.execute(
            "INSERT INTO users (key_hash, pk_pub) VALUES (X'00', X'00');",
            [],
        )
        .expect("Failed to insert user");

        conn.execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .expect("Failed to insert group");

        conn.execute(
            "INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00');",
            [],
        )
        .expect("Failed to insert group user junction");

        conn.execute(
            "INSERT INTO files (group_id, filename, path) VALUES (1, 'test_file.txt', '/path/to/test_file.txt');",
            [],
        )
        .expect("Failed to insert file");
    }

    #[test]
    fn test_get_files_for_user() {
        let conn = Connection::open_in_memory().unwrap();
        setup_test_db(&conn);

        let user_id = 1;
        let result = get_files_for_user_id(&conn, user_id).unwrap();

        assert_eq!(
            result,
            vec![("test_file.txt".to_string(), 1, "group_name".to_string(), 1)]
        );
    }

    #[test]
    fn test_get_files_for_nonexisting_user() {
        let conn = Connection::open_in_memory().unwrap();
        setup_test_db(&conn);

        let user_id = 1000; // does not exist in the testing db
        let result = get_files_for_user_id(&conn, user_id).unwrap();

        assert_eq!(result, Vec::<(String, i32, String, i32)>::new());
    }
}
