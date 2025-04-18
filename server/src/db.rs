use corelib::server::salt_password;
use rusqlite::{Connection, Result, params, params_from_iter, types::Value};
use std::path::Path;
use std::rc::Rc;

pub(crate) struct Database {
    pub(crate) conn: Connection,
}

impl Database {
    pub fn open<P: AsRef<Path>>(filepath: P) -> Result<Self> {
        let conn = Connection::open(filepath)?;
        rusqlite::vtab::array::load_module(&conn)?;
        Ok(Database { conn })
    }
}

/// initialize all expected tables within a database connection
///
/// has no side effects if these tables already exist
///
/// NOTE: will not update an existing table, so in the case of a migration
/// simply changing the schema within this function will not migrate existing tables
pub fn init_db(Database { conn }: &mut Database) -> Result<()> {
    let sql = "
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        password_hash BLOB NOT NULL,
        salt BLOB NOT NULL,
        pk_pub BLOB NOT NULL,
        UNIQUE(email)
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
    Database { conn }: &Database,
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

/// Retrieves the filename, group name, and group ID for a given file ID and user ID.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `user_id` - The ID of the user whose files are to be retrieved.
/// * `file_id` - The ID of the file to retrieve.
///
/// # Returns
///
/// A `Result` containing a tuple of the filename, group name, and group ID.
pub fn get_file_info(
    Database { conn }: &Database,
    user_id: i64,
    file_id: i64,
) -> Result<(String, String, i64)> {
    let query = "
        SELECT f.filename, guj.name, guj.group_id
        FROM files f
        JOIN groups_user_junction guj 
            ON f.group_id = guj.group_id
        WHERE guj.user_id = ? AND f.file_id = ?;
    ";
    let mut statement = conn.prepare(query).expect("unable to prepare query");

    statement.query_row([user_id, file_id], |row| {
        Ok((
            row.get::<usize, String>(0)?,
            row.get::<usize, String>(1)?,
            row.get::<usize, i64>(2)?,
        ))
    })
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
pub fn get_user_id(
    Database { conn }: &Database,
    user_email: &str,
    user_password_hash: &[u8],
) -> Result<i64> {
    // first, fetch the salt
    let query = "
        SELECT salt FROM users WHERE email = ?;
    ";
    let mut statement = conn.prepare(query).expect("Unable to prepare salt query");
    let salt = statement.query_row(params![user_email], |row| row.get::<usize, Vec<u8>>(0))?;
    let hashed_password = salt_password(user_password_hash, salt.as_slice());

    // then attempt to fetch the matching id
    let query = "
        SELECT id FROM users WHERE email = ? AND password_hash = ?;
    ";
    let mut statement = conn.prepare(query).expect("unable to prepare query");
    statement.query_row(params![user_email, hashed_password], |row| row.get(0))
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
pub fn insert_file(Database { conn }: &mut Database, group_id: i64, filename: &str) -> Result<i64> {
    let sql = "
        INSERT INTO files (group_id, filename) VALUES (?, ?)
        RETURNING file_id;
    ";
    let mut statement = conn.prepare(sql).unwrap();
    statement.query_row(params![group_id, filename], |row| row.get::<usize, i64>(0))
}

/// Retrieves a list of all users in the given group.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `group_id` - The ID of the group to query.
///
/// # Returns
///
/// A `Result` containing a vector of tuples, where each tuple contains the email and user ID of a user in the group.
pub fn get_group(Database { conn }: &Database, group_id: i64) -> Result<Vec<(String, i64)>> {
    let sql = "
        SELECT email, id FROM users u LEFT JOIN groups_user_junction g ON u.id = g.user_id WHERE g.group_id = ?;
    ";
    let mut statement = conn.prepare(sql).unwrap();
    statement
        .query_map([group_id], |row| {
            Ok((row.get::<usize, String>(0)?, row.get::<usize, i64>(1)?))
        })?
        .collect()
}
/// Retrieves the encrypted key for a given group and user.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `group_id` - The ID of the group to query.
/// * `user_id` - The ID of the user to query.
///
/// # Returns
///
/// A `Result` containing the encrypted key as a `Vec<u8>`.
pub fn get_group_key(Database { conn }: &Database, group_id: i64, user_id: i64) -> Result<Vec<u8>> {
    let sql = "
        SELECT encrypted_key FROM groups_user_junction WHERE group_id = ? AND user_id = ?;
    ";
    let mut statement = conn.prepare(sql).unwrap();
    statement.query_row(params![group_id, user_id], |row| row.get(0))
}
/// Retrieves a list of all the users with the given emails/ids that exist in the database.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `users` - A vector of tuples, where each tuple contains the user ID and email of a user.
///
/// # Returns
///
/// A `Result` containing a vector of tuples, where each tuple contains the user ID and email of a user
/// that exists in the database.
pub fn get_existing_users(
    Database { conn }: &Database,
    users: Vec<(i64, String)>,
) -> Result<Vec<(i64, String)>> {
    // use a repeated statement because we can't use rarray
    // since rarray requires Rc<Vec<Value>>, and Value is only
    // Text, Integer, Real, or Blob. We need a tuple, so we do it ourselves
    let mut repeated = "(?, ?),".repeat(users.len());
    repeated.pop(); // remove the last comma
    let sql = format!("SELECT id, email FROM users WHERE (id, email) IN ({repeated});");
    let mut statement = conn.prepare(&sql).unwrap();

    let params = users
        .into_iter()
        .flat_map(|u| vec![Value::Integer(u.0), Value::Text(u.1)]);
    statement
        .query_map(params_from_iter(params), |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect()
}

/// Inserts the user with the given email and password hash into the database.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `user_email` - The user email.
/// * `user_password_hash` - The user's salted and hashed password.
/// * `salt` - The salt (random value used with password to create password hash)
/// * `pub_key` - The public key for the user
///
/// # Returns
///
/// A `Result` containing the ID of the newly created user
pub fn register_user(
    Database { conn }: &Database,
    user_email: &str,
    user_password_hash: Vec<u8>,
    salt: [u8; 8],
    key: Vec<u8>,
) -> Result<i64> {
    let query: &str = "
        INSERT INTO users (email, password_hash, salt, pk_pub)
        VALUES (?, ?, ?, ?)
        RETURNING id;";
    let mut statement = conn
        .prepare(query)
        .expect("Unable to prepare user insert statement");
    statement.query_row(params![user_email, user_password_hash, salt, key], |row| {
        row.get::<usize, i64>(0)
    })
}

/// Retrieves the group ID for a given list of user IDs.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `members` - A vector of user IDs.
///
/// # Returns
///
/// A `Result` containing the group ID if a group exists containing all of
/// the specified users, or `None` if no group exists.
pub fn get_group_id(Database { conn }: &Database, members: Vec<i64>) -> Result<Option<i64>> {
    // query the database
    let sql = "
    SELECT group_id FROM groups_user_junction
    GROUP BY group_id
    HAVING COUNT(DISTINCT CASE WHEN user_id IN rarray(?1) THEN user_id END) = ?2
    AND COUNT(DISTINCT CASE WHEN user_id NOT IN rarray(?1) THEN user_id END) = 0;";
    let mut statement = conn.prepare(sql).unwrap();
    let user_id_vec: Rc<Vec<Value>> = Rc::new(members.iter().map(|u| Value::Integer(*u)).collect());
    let group_ids: Result<Vec<i64>> = statement
        .query_map(params![user_id_vec, members.len()], |row| {
            Ok(row.get::<usize, i64>(0)?)
        })?
        .collect();
    let group_ids = group_ids?;

    // make sure only one group matches
    // and return that group, or None if no groups match
    if group_ids.len() > 0 {
        assert!(group_ids.len() == 1); // somehow backend messed up
        Ok(Some(group_ids[0]))
    } else {
        Ok(None)
    }
}

/// Creates a new group in the database with the given members.
/// This should only be called after checking if one already exists.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `members` - A vector of tuples, where each tuple contains the user ID and encrypted key of a user.
///
/// # Returns
///
/// A `Result` containing the ID of the newly created group.
pub fn create_group(Database { conn }: &mut Database, members: Vec<(i64, Vec<u8>)>) -> Result<i64> {
    // insert group
    let sql = "
        INSERT INTO groups VALUES (NULL) RETURNING id;
    ";
    let mut statement = conn
        .prepare(sql)
        .expect("Failed to prepare group insert statement");
    let group_id = statement.query_row([], |row| row.get::<usize, i64>(0))?;

    // insert members
    // note: group_id is an integer from us, so no need to escape it
    let mut repeated_part =
        format!("({group_id}, ?, 'group_{group_id}', ?),").repeat(members.len());
    repeated_part.pop();
    let sql = format!(
        "INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES {repeated_part};"
    );
    let mut statement = conn
        .prepare(&sql)
        .expect("Failed to prepare insert statement for groups_user_junction");
    statement.execute(rusqlite::params_from_iter(
        members
            .into_iter()
            .flat_map(|m| vec![Value::Integer(m.0), Value::Blob(m.1)]),
    ))?;

    // return new group id
    Ok(group_id)
}

/// Retrieves all groups for a given user ID.
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `user_id` - The ID of the user.
///
/// # Returns
///
/// A `Result` containing a vector of tuples, where each tuple contains the group ID and name.
pub fn get_groups_for_user_id(
    Database { conn }: &Database,
    user_id: i64,
) -> Result<Vec<(i64, String)>> {
    let sql = "
        SELECT group_id, name FROM groups_user_junction WHERE user_id = ?;
    ";
    let mut statement = conn.prepare(sql).unwrap();
    statement
        .query_map([user_id], |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect()
}

/// Retrieves the public key for the given user ID
///
/// # Arguments
///
/// * `conn` - A reference to the SQLite database connection.
/// * `user_id` - the ID of the user
///
/// # Returns
///
/// A `Result` containing the user's public key, in bytes
pub fn get_user_key(Database { conn }: &Database, user_id: i64) -> Result<Vec<u8>> {
    let sql = "
        SELECT pk_pub FROM users WHERE id = ?;
    ";
    let mut statement = conn.prepare(sql).unwrap();

    statement.query_row(params![user_id], |row| row.get(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use corelib::server::make_salt;

    fn setup_test_db() -> Database {
        let mut db = Database::open(":memory:").unwrap();
        init_db(&mut db).unwrap();

        // create fake records
        let salt = make_salt();
        let password_hash = salt_password(b"00", &salt);
        db.conn.execute(
            "INSERT INTO users (email, salt, password_hash, pk_pub) VALUES ('test@test.com', ?, ?, X'00');",
            params![salt, password_hash],
        )
        .expect("Failed to insert user");

        db.conn
            .execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .expect("Failed to insert group");

        db.conn.execute(
            "INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 1, 'group_name', X'00');",
            [],
        )
        .expect("Failed to insert group user junction");

        db.conn
            .execute(
                "INSERT INTO files (group_id, filename) VALUES (1, 'test_file.txt');",
                [],
            )
            .expect("Failed to insert file");

        db
    }

    #[test]
    fn test_get_files_for_user() {
        let db = setup_test_db();

        let user_id = 1;
        let result = get_files_for_user_id(&db, user_id).unwrap();

        assert_eq!(
            result,
            vec![("test_file.txt".to_string(), 1, "group_name".to_string(), 1)]
        );
    }

    #[test]
    fn test_get_files_for_nonexisting_user() {
        let db = setup_test_db();

        let user_id = 1000; // does not exist in the testing db
        let result = get_files_for_user_id(&db, user_id).unwrap();

        assert_eq!(result, Vec::<(String, i64, String, i64)>::new());
    }

    #[test]
    fn test_get_user_id_existing() {
        let db = setup_test_db();

        // get user id for 'test'
        let result = get_user_id(&db, "test@test.com", b"00").unwrap();
        assert_eq!(result, 1);

        // try with another
        let salt = make_salt();
        let password_hash = salt_password(b"AFF3", &salt);
        db.conn.execute(
            "INSERT INTO users(email, password_hash, salt, pk_pub) VALUES ('test2@test2.com', ?, ?, X'00');",
            params![password_hash, salt],
        )
        .expect("Failed to execute insert");
        let result2 = get_user_id(&db, "test2@test2.com", b"AFF3").unwrap();
        assert_eq!(result2, 2);
    }
    #[test]
    fn test_get_user_id_mismatch_hash() {
        let db = setup_test_db();

        // get user id for nonexistent person
        assert!(get_user_id(&db, "test@test.com", b"01").is_err());
    }
    #[test]
    fn test_get_user_id_mismatch_email() {
        let db = setup_test_db();

        // get user id for nonexistent person
        assert!(get_user_id(&db, "nest@test.com", b"00").is_err());
    }
    #[test]
    fn test_insert_file() {
        let mut db = setup_test_db();

        let file_id = insert_file(&mut db, 1, "test_file.txt").unwrap();
        assert_eq!(file_id, 2);
        // should work with similar group id / filename since fileid is primary key
        let file_id = insert_file(&mut db, 1, "test_file.txt").unwrap();
        assert_eq!(file_id, 3);
        // and also with others
        let file_id = insert_file(&mut db, 1, "test_file2.txt").unwrap();
        assert_eq!(file_id, 4);
    }
    #[test]
    fn test_insert_file_nonexistent_group_id() {
        let mut db = setup_test_db();

        assert!(insert_file(&mut db, 2, "test_file.txt").is_err());
    }
    #[test]
    fn test_get_file_info() {
        let db = setup_test_db();

        let result = get_file_info(&db, 1, 1).unwrap();
        assert_eq!(
            result,
            ("test_file.txt".to_string(), "group_name".to_string(), 1)
        );

        // and try with a new one
        db.conn
            .execute(
                "INSERT INTO files (group_id, filename) VALUES (1, 'test_file2.txt');",
                [],
            )
            .expect("Failed to insert file");
        let result = get_file_info(&db, 1, 2).unwrap();
        assert_eq!(
            result,
            ("test_file2.txt".to_string(), "group_name".to_string(), 1)
        );

        // try getting file info for a file that isn't shared with me
        db.conn.execute_batch("
            INSERT INTO groups (id) VALUES (NULL);
            INSERT INTO users (email, salt, password_hash, pk_pub) VALUES ('test2@test.com', X'00', X'00', X'00');
            INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (2, 2, 'second', X'00');
            INSERT INTO files (group_id, filename) VALUES (2, 'privatefile');
        ").expect("Failed to insert items");
        // user 2 should be able to get it
        let result = get_file_info(&db, 2, 3).unwrap();
        assert_eq!(result, ("privatefile".to_string(), "second".to_string(), 2));
        // and user 1 shouldn't
        let result = get_file_info(&db, 1, 3);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_group() {
        let db = setup_test_db();

        // query current database
        let result = get_group(&db, 1);
        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "test@test.com");
        assert_eq!(result[0].1, 1);

        // and try with a new group too
        db.conn.execute("INSERT INTO users (email, salt, password_hash, pk_pub) VALUES ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00'), ('test4@test.com', X'00', X'00', X'00');", []).expect("Failed to execute insert");
        db.conn
            .execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .expect("Failed to execute insert");
        db.conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (2, 2, 'group_name', X'00'), (2, 3, 'group_name', X'00'), (2, 4, 'group_name', X'00');", []).expect("Failed to insert into groups_user_junction");
        let result = get_group(&db, 2);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, "test2@test.com");
        assert_eq!(result[0].1, 2);
        assert_eq!(result[1].0, "test3@test.com");
        assert_eq!(result[1].1, 3);
        assert_eq!(result[2].0, "test4@test.com");
        assert_eq!(result[2].1, 4);
    }

    #[test]
    fn test_get_group_key() {
        let db = setup_test_db();
        db.conn.execute("INSERT INTO users (email, salt, password_hash, pk_pub) VALUES ('test2@test.com', X'00', X'00', X'00');", []).expect("Failed to insert");
        db.conn
            .execute("INSERT INTO groups (id) VALUES (NULL);", [])
            .expect("Failed to insert");
        db.conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 2, 'group_name', X'01'), (2, 1, 'group_name', X'02'), (2, 2, 'group_name', X'03');", []).expect("Failed to insert");

        // should allow different keys for different (user, group) pairs
        let result = get_group_key(&db, 1, 1).unwrap();
        assert_eq!(result, vec![0u8]);
        let result = get_group_key(&db, 1, 2).unwrap();
        assert_eq!(result, vec![1u8]);
        let result = get_group_key(&db, 2, 1).unwrap();
        assert_eq!(result, vec![2u8]);
        let result = get_group_key(&db, 2, 2).unwrap();
        assert_eq!(result, vec![3u8]);
    }

    #[test]
    fn test_get_existing_users() {
        let db = setup_test_db();
        db.conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00'), ('test4@test.com', X'00', X'00', X'00');", []).expect("Failed to insert into users");

        // test with id/email mismatch
        let result = get_existing_users(
            &db,
            vec![
                (1, "test2@test.com".to_string()),
                (2, "test3@test.com".to_string()),
                (3, "test@test.com".to_string()),
            ],
        )
        .unwrap();
        assert_eq!(result, vec![]);

        // test with proper id/email pairs
        let result = get_existing_users(
            &db,
            vec![
                (2, "test2@test.com".to_string()),
                (3, "test3@test.com".to_string()),
                (1, "test@test.com".to_string()),
            ],
        )
        .unwrap();
        assert_eq!(
            result,
            vec![
                (2, "test2@test.com".to_string()),
                (3, "test3@test.com".to_string()),
                (1, "test@test.com".to_string()),
            ]
        );
    }

    #[test]
    fn test_get_group_id() {
        let db = setup_test_db();
        db.conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00'), ('test4@test.com', X'00', X'00', X'00');", []).expect("Failed to insert into users");
        db.conn
            .execute("INSERT INTO groups VALUES (NULL);", [])
            .expect("Failed to insert into groups");
        db.conn
            .execute("INSERT INTO groups VALUES (NULL);", [])
            .expect("Failed to insert into groups");
        db.conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (1, 2, 'group1', X'00'), (1, 3, 'group1', X'00'), (1, 4, 'group1', X'00'), (2, 1, 'group1', X'00'), (2, 3, 'group1', X'00'), (3, 1, 'group1', X'00'), (3, 4, 'group1', X'00');", []).expect("Failed to insert into groups_user_junction");

        // query the big group
        let result = get_group_id(&db, vec![1, 2, 3, 4]).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 1);

        // query smaller groups
        let result = get_group_id(&db, vec![1, 3]).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 2);
        let result = get_group_id(&db, vec![1, 4]).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 3);

        // and try nonexistent group
        let result = get_group_id(&db, vec![2, 4]).unwrap();
        assert!(result.is_none());
        // and try with duplicates
        let result = get_group_id(&db, vec![1, 2, 3, 1]).unwrap();
        assert!(result.is_none());
        let result = get_group_id(&db, vec![1, 3, 1]).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_create_group() {
        let mut db = setup_test_db();
        db.conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test2@test.com', X'00', X'00', X'00'), ('test3@test.com', X'00', X'00', X'00'), ('test4@test.com', X'00', X'00', X'00');", []).expect("Failed to insert into users");

        // create group containing user 1 and user 2
        let result = create_group(&mut db, vec![(1, vec![0u8]), (2, vec![1u8])]).unwrap();
        assert_eq!(result, 2);
        let user_key = db
            .conn
            .query_row(
                "SELECT encrypted_key FROM groups_user_junction WHERE group_id = 2 AND user_id = 1",
                [],
                |row| row.get::<usize, Vec<u8>>(0),
            )
            .unwrap();
        assert_eq!(user_key, vec![0u8]);
        let user_key = db
            .conn
            .query_row(
                "SELECT encrypted_key FROM groups_user_junction WHERE group_id = 2 AND user_id = 2",
                [],
                |row| row.get::<usize, Vec<u8>>(0),
            )
            .unwrap();
        assert_eq!(user_key, vec![1u8]);
    }

    #[test]
    fn test_get_groups_for_user_id() {
        let db = setup_test_db();

        db.conn
            .execute("INSERT INTO groups VALUES (NULL);", [])
            .unwrap();
        db.conn
            .execute("INSERT INTO groups VALUES (NULL);", [])
            .unwrap();
        db.conn
            .execute("INSERT INTO groups VALUES (NULL);", [])
            .unwrap();
        db.conn.execute("INSERT INTO groups_user_junction (group_id, user_id, name, encrypted_key) VALUES (2, 1, 'group2', X'00'), (3, 1, 'group3', X'00'), (4, 1, 'group4', X'00');", []).unwrap();

        let result = get_groups_for_user_id(&db, 1).unwrap();
        assert_eq!(
            result,
            vec![
                (1, "group_name".to_string()),
                (2, "group2".to_string()),
                (3, "group3".to_string()),
                (4, "group4".to_string())
            ]
        );

        // test nonexistent
        let result = get_groups_for_user_id(&db, 2).unwrap();
        assert_eq!(result, vec![]);
    }

    #[test]
    fn test_get_user_key() {
        let db = setup_test_db();

        let pk_pub = vec![22u8]; // add a second user
        db.conn.execute("INSERT INTO users (email, password_hash, salt, pk_pub) VALUES ('test2@test.com', X'02', X'01', ?);", [pk_pub.clone()]).unwrap();

        let result = get_user_key(&db, 1).unwrap();
        assert_eq!(result, [0u8]); // the one from setup_test_db
        let result = get_user_key(&db, 2).unwrap();
        assert_eq!(result, pk_pub);
    }

    #[test]
    fn test_register_user() {
        let db = setup_test_db();

        let salt: [u8; 8] = [0; 8];
        let password_hash = b"PASSWORD".to_vec();
        let pwd = password_hash.clone();

        let result =
            register_user(&db, &"email@domain.com", password_hash, salt, vec![22u8]).unwrap();

        let uid: i64 = db
            .conn
            .query_row(
                "SELECT id FROM users WHERE email = ? AND password_hash = ?;",
                params![&"email@domain.com", pwd],
                |row| row.get::<usize, i64>(0),
            )
            .unwrap();

        assert_eq!(result, uid);
    }
}
