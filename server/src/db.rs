pub const DB_NAME: &str = "e2ee-file-sharing.db";
use corelib::server::salt_password;
use rusqlite::{Connection, Result, params};

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
        email TEXT NOT NULL,
        password_hash BLOB NOT NULL,
        salt BLOB NOT NULL,
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
        filename TEXT NOT NULL
    );";
    conn.execute_batch(sql)
}

/// Retrieves a list of files associated with a given user ID.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `user_id` - The ID of the user whose files are to be retrieved.
///
/// # Returns
///
/// A `Result` containing a vector of tuples, where each tuple consists of:
/// - `String`: The filename.
/// - `i64`: The file ID.
/// - `String`: The group name to which the file belongs.
/// - `i64`: The group ID.
pub fn get_files_for_user_id(
    conn: &Connection,
    user_id: i64,
) -> Result<Vec<(String, i64, String, i64)>> {
    let query = "
        SELECT f.filename, f.file_id, guj.name, guj.group_id
        FROM files f
        JOIN groups_user_junction guj 
            ON f.group_id = guj.group_id
        WHERE guj.user_id = ?;
    ";

    let mut statement = conn.prepare(query).expect("unable to prepare query");

    statement
        .query_map([user_id], |row| {
            Ok((
                row.get::<usize, String>(0)?,
                row.get::<usize, i64>(1)?,
                row.get::<usize, String>(2)?,
                row.get::<usize, i64>(3)?,
            ))
        })?
        .collect()
}

/// Retrieves the user ID from the database for a given email and password hash.
///
/// This function queries the `users` table to find a user with the specified
/// email and password hash. If a match is found, the user ID is returned.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `user_email` - The email of the user to authenticate.
/// * `user_password_hash` - The hashed password of the user to authenticate.
///
/// # Returns
///
/// A `Result` containing the user ID as an `i64` if the user is found, or an
/// error if the user cannot be authenticated.
pub fn get_user_id(conn: &Connection, user_email: &str, user_password_hash: &str) -> Result<i64> {
    // first, fetch the salt
    let query = "
        SELECT salt FROM users WHERE email = ?;
    ";
    let mut statement = conn.prepare(query).expect("Unable to prepare salt query");
    let salt = statement.query_row(params![user_email], |row| row.get::<usize, Vec<u8>>(0))?;

    // then attempt to fetch the matching id
    let query = "
        SELECT id FROM users WHERE email = ? AND password_hash = ?;
    ";
    let mut statement = conn.prepare(query).expect("unable to prepare query");
    statement.query_row(
        params![
            user_email,
            salt_password(user_password_hash, salt.as_slice())
        ],
        |row| row.get(0),
    )
}

/// Inserts a file into the database.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `group_id` - The ID of the group to which the file belongs.
/// * `filename` - The name of the file.
///
/// # Returns
///
/// A `Result` containing the ID of the newly inserted file.
pub fn insert_file(conn: &Connection, group_id: i64, filename: &str) -> Result<i64> {
    let sql = "
        INSERT INTO files (group_id, filename) VALUES (?, ?)
        RETURNING file_id;
    ";
    let mut statement = conn.prepare(sql).unwrap();
    statement.query_row(params![group_id, filename], |row| row.get::<usize, i64>(0))
}
/// Retrieves the filename associated with a given file ID.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `file_id` - The ID of the file to query.
///
/// # Returns
///
/// A `Result` containing the filename as a `String`.
pub fn get_filename(conn: &Connection, file_id: i64) -> Result<String> {
    let sql = "
        SELECT filename FROM files WHERE file_id = ?;
    ";
    let mut statement = conn.prepare(sql).unwrap();
    statement.query_row([file_id], |row| row.get::<usize, String>(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corelib::server::make_salt;
    use rusqlite::Connection;

    fn setup_test_db(conn: &Connection) {
        init_db(&conn).unwrap();

        // create fake records
        let salt = make_salt();
        let password_hash = salt_password("00", &salt);
        conn.execute(
            "INSERT INTO users (email, salt, password_hash, pk_pub) VALUES ('test@test.com', ?, ?, X'00');",
            params![salt, password_hash],
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
            "INSERT INTO files (group_id, filename) VALUES (1, 'test_file.txt');",
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

        assert_eq!(result, Vec::<(String, i64, String, i64)>::new());
    }

    #[test]
    fn test_get_user_id_existing() {
        let conn = Connection::open_in_memory().unwrap();
        setup_test_db(&conn);

        // get user id for 'test'
        let result = get_user_id(&conn, "test@test.com", "00").unwrap();
        assert_eq!(result, 1);

        // try with another
        let salt = make_salt();
        let password_hash = salt_password("AFF3", &salt);
        conn.execute(
            "INSERT INTO users(email, password_hash, salt, pk_pub) VALUES ('test2@test2.com', ?, ?, X'00');",
            params![password_hash, salt],
        )
        .expect("Failed to execute insert");
        let result2 = get_user_id(&conn, "test2@test2.com", "AFF3").unwrap();
        assert_eq!(result2, 2);
    }
    #[test]
    fn test_get_user_id_mismatch_hash() {
        let conn = Connection::open_in_memory().unwrap();
        setup_test_db(&conn);

        // get user id for nonexistent person
        assert!(get_user_id(&conn, "test@test.com", "01").is_err());
    }
    #[test]
    fn test_get_user_id_mismatch_email() {
        let conn = Connection::open_in_memory().unwrap();
        setup_test_db(&conn);

        // get user id for nonexistent person
        assert!(get_user_id(&conn, "nest@test.com", "00").is_err());
    }
    #[test]
    fn test_insert_file() {
        let conn = Connection::open_in_memory().unwrap();
        setup_test_db(&conn);

        let file_id = insert_file(&conn, 1, "test_file.txt").unwrap();
        assert_eq!(file_id, 2);
        // should work with similar group id / filename since fileid is primary key
        let file_id = insert_file(&conn, 1, "test_file.txt").unwrap();
        assert_eq!(file_id, 3);
        // and also with others
        let file_id = insert_file(&conn, 1, "test_file2.txt").unwrap();
        assert_eq!(file_id, 4);
    }
    #[test]
    fn test_insert_file_nonexistent_group_id() {
        let conn = Connection::open_in_memory().unwrap();
        setup_test_db(&conn);

        assert!(insert_file(&conn, 2, "test_file.txt").is_err());
    }
    #[test]
    fn test_get_filename() {
        let conn = Connection::open_in_memory().unwrap();
        setup_test_db(&conn);

        let result = get_filename(&conn, 1).unwrap();
        assert_eq!(result, "test_file.txt");

        // and try with a new one
        conn.execute(
            "INSERT INTO files (group_id, filename) VALUES (1, 'test_file2.txt');",
            [],
        )
        .expect("Failed to insert file");
        let result = get_filename(&conn, 2).unwrap();
        assert_eq!(result, "test_file2.txt");
    }

    #[test]
    fn test_get_filename_nonexistent() {
        let conn = Connection::open_in_memory().unwrap();
        setup_test_db(&conn);

        // get nonexistent
        assert!(get_filename(&conn, 2).is_err());
    }
}
