use std::{
    collections::VecDeque,
    error::Error,
    fs::{self, OpenOptions},
    io::{self, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE, Engine as _};
use corelib::client::{
    DiskKeys, GroupKey, PersonalKey, PkKeyPair,
    file_stream_encryption::{CHUNK_SIZE, FileStreamEncryptor, MAC_SIZE, NETWORK_CHUNK_SIZE},
};
use models::*;
use reqwest::StatusCode;
use rpassword::read_password;
use rsa::pkcs8::DecodePublicKey;
use tungstenite::{Bytes, Message, Utf8Bytes};

/// Decrypts the user's private key and fetches their user info from the server
///
/// # Arguments
///
/// * `server_url` - The URL of the server
/// * `email` - The email of the user
/// * `password` - The password of the user
/// * `disk_key_path` - The path to the disk key directory
///
/// # Returns
///
/// A `Result` containing the user's key pair, their password hash, and their user id
pub fn get_user_info(
    server_url: &str,
    email: &str,
    password: &str,
    disk_key_path: &Path,
) -> Result<(PkKeyPair, String, i64), Box<dyn Error>> {
    // look in storage to recover our kp and key hash
    let bytes = fs::read(disk_key_path.join(email))?;
    let keys: DiskKeys = postcard::from_bytes(bytes.as_slice())?;
    let personal_key = PersonalKey::derive(email, password);
    let kp = keys.to_memory(&personal_key);
    let encoded_password = BASE64_URL_SAFE.encode(personal_key.hash().to_vec());

    // double check that password is correct
    // by fetching to user info endpoint
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(format!(
            "{server_url}/api/v1/user/info?user_email={email}&user_password_hash={encoded_password}",
        ))
        .send()?;
    if !resp.status().is_success() {
        return Err(Box::from(format!(
            "Server responded to user info request with:\nStatus: {}\nResponse: {}",
            resp.status(),
            resp.text()?
        )));
    }
    let info: UserId = resp.json()?;
    let user_id = info.user_id;
    Ok((kp, encoded_password, user_id))
}

/// Register a new user
///
/// # Arguments
///
/// * `server_url` - The URL of the server
/// * `email` - The email of the user
/// * `password` - The password of the user
/// * `disk_key_path` - The path to the disk key directory
pub fn register(
    server_url: &str,
    email: &str,
    password: &str,
    disk_key_path: &Path,
) -> Result<(), Box<dyn Error>> {
    // confirm password
    eprint!("Confirm password: ");
    io::stderr().flush()?;
    if password != read_password()? {
        return Err(Box::from("Passwords do not match"));
    }

    // passwords match
    // first, check if we already have a key
    if fs::exists(disk_key_path.join(email))? {
        return Err(Box::from(
            "User disk key already exists.\nPlease remove this file to register a user with the provided email, or use a different email.",
        ));
    }

    // no key, so let's create one
    // create our personal_key and keypair
    eprintln!("Registering user...");
    let personal_key = PersonalKey::derive(email, password);
    let kp = PkKeyPair::new();
    let pk_pub = kp.get_public_key_pem()?;
    let keys = DiskKeys::new(&personal_key, &kp);

    // send registration request
    let client = reqwest::blocking::Client::new();
    let json = serde_json::json!({
        "user_email": email,
        "user_password_hash": BASE64_STANDARD.encode(personal_key.hash()),
        "key": BASE64_STANDARD.encode(&pk_pub),
    });
    let req = client
        .post(format!("{server_url}/api/v1/user"))
        .json(&json)
        .send()?;
    if !req.status().is_success() {
        return Err(Box::from(format!(
            "Server responded with:\nStatus: {}\nResponse: {}",
            req.status(),
            req.text()?
        )));
    }

    // encrypt and store
    // choice of postcard because it does well on benchmarks:
    // https://github.com/djkoloski/rust_serialization_benchmark
    let bytes = postcard::to_stdvec(&keys)?.to_vec();
    fs::write(disk_key_path.join(email), bytes)?;
    Ok(())
}

/// Fetches the group key from the server
/// and decrypts it using the user's private key
///
/// # Arguments
///
/// * `server_url` - The URL of the server
/// * `email` - The email of the user
/// * `encoded_password` - The encoded password of the user
/// * `group_id` - The id of the group
/// * `kp` - The user's key pair
/// * `client` - The client to use to make requests
///
/// # Returns
///
/// A `Result` containing the group key
fn get_group_key(
    server_url: &str,
    email: &str,
    encoded_password: &str,
    group_id: i64,
    kp: &PkKeyPair,
    client: &reqwest::blocking::Client,
) -> Result<GroupKey, Box<dyn Error>> {
    let resp = client
        .get(format!(
            "{server_url}/api/v1/group/{group_id}/key?user_email={email}&user_password_hash={encoded_password}",
        ))
        .send()?;
    if !resp.status().is_success() {
        return Err(Box::from(format!(
            "Server responded to group key request with:\nStatus: {}\nResponse: {}",
            resp.status(),
            resp.text()?
        )));
    }
    let group_key_response: Key = resp.json()?; // gets the encoded, encrypted aes group key
    // decode it
    let group_key_decoded = BASE64_STANDARD.decode(&group_key_response.key)?;
    // and finally decrypt it
    let group_key = kp.get_group_key(&group_key_decoded);
    Ok(group_key)
}

/// Downloads a file from the server by using
/// the provided id and decrypts it using the user's private key
/// and the group's key, saving it to the provided path.
/// If no path is provided, the file will be saved as the file name provided by the server.
/// Returns an error if the file already exists.
///
/// # Arguments
///
/// * `server_url` - the url of the server
/// * `email` - the email of the user
/// * `encoded_password` - the base64-encoded password of the user
/// * `kp` - the key pair of the user
/// * `file_id` - the id of the file to download
/// * `output` - the path to save the file to
pub fn download(
    server_url: &str,
    email: &str,
    encoded_password: &str,
    kp: &PkKeyPair,
    file_id: i64,
    output: Option<PathBuf>,
    stdout: bool,
) -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::new();
    // make request to file info endpoint
    let resp = client
        .get(format!(
            "{server_url}/api/v1/file/{file_id}/info?user_email={email}&user_password_hash={encoded_password}"
        ))
        .send()?;
    if !resp.status().is_success() {
        return Err(Box::from(format!(
            "Server responded to file info request with:\nStatus: {}\nResponse: {}",
            resp.status(),
            resp.text()?
        )));
    }
    // parse the response
    let info: FileInfo = resp.json()?;
    let mut output_stream: Box<dyn Write> = match output {
        Some(path) => {
            if stdout {
                eprintln!("--stdout ignored because --output was specified");
            }
            Box::new(OpenOptions::new().create(true).append(true).open(&path)?)
        }
        None => {
            if stdout {
                Box::new(BufWriter::new(std::io::stdout()))
            } else {
                let result = fs::exists(&info.file_name)?;
                if result {
                    return Err(Box::from("File already exists!"));
                } else {
                    let tmp = PathBuf::from(&info.file_name);
                    Box::new(OpenOptions::new().create(true).append(true).open(&tmp)?)
                }
            }
        }
    };

    // get group key
    let group_key = get_group_key(
        server_url,
        email,
        encoded_password,
        info.group_id,
        kp,
        &client,
    )?;

    // make request to file endpoint
    let mut resp = client
        .get(format!(
            "{server_url}/api/v1/file?file_id={file_id}&user_email={email}&user_password_hash={encoded_password}",
        ))
        .send()?;
    if !resp.status().is_success() {
        return Err(Box::from(format!(
            "Server responded to file download request with:\nStatus: {}\nResponse: {}",
            resp.status(),
            resp.text()?
        )));
    }

    let cipher = group_key.get_cipher();

    let mut nonce_start: [u8; 8] = [0; 8];
    resp.read_exact(&mut nonce_start)?;

    let fse = FileStreamEncryptor::new_with_nonce_start(cipher, nonce_start);

    let mut buf: VecDeque<u8> = VecDeque::new();
    let mut net_chunk: [u8; NETWORK_CHUNK_SIZE] = [0; NETWORK_CHUNK_SIZE];
    let mut curr_ind: u32 = 0;

    loop {
        let bytes_read = resp.read(&mut net_chunk)?;
        if bytes_read == 0 {
            break;
        }

        buf.extend(net_chunk[..bytes_read].iter().copied());

        while buf.len() > CHUNK_SIZE + MAC_SIZE {
            let chunk: Vec<u8> = buf.drain(..(CHUNK_SIZE + MAC_SIZE)).collect();
            let decrypted_chunk = fse.decrypt_chunk(chunk.as_slice(), curr_ind)?;
            output_stream.write_all(&decrypted_chunk)?;
            curr_ind += 1;
        }
    }

    // potentially, the final chunk is remaining after the loop has finished
    if !buf.is_empty() {
        let decrypted_bytes = fse.decrypt_chunk(buf.make_contiguous(), curr_ind)?;
        output_stream.write_all(&decrypted_bytes)?;
    }

    output_stream.flush()?;
    Ok(())
}

/// Creates a group on the server and returns the group id
///
/// # Arguments
///
/// * `server_url` - the url of the server
/// * `email` - the email of the user
/// * `encoded_password` - the base64-encoded password of the user
/// * `ids` - the ids of the users to add to the group
/// * `members` - the members of the group
/// * `client` - the client to use to make requests
///
/// # Returns
///
/// A `Result` containing the group id
fn create_group(
    server_url: &str,
    email: &str,
    encoded_password: &str,
    ids: Vec<i64>,
    members: GroupMembers,
    client: &reqwest::blocking::Client,
) -> Result<i64, Box<dyn Error>> {
    // need to make a group
    // get every pkpub for each user
    let mut pkpubs = Vec::new();
    for id in ids {
        let resp = client.get(format!(
                        "{server_url}/api/v1/user/key?target_user_id={id}&user_email={email}&user_password_hash={encoded_password}",
                    )).send()?;
        if !resp.status().is_success() {
            return Err(Box::from(format!(
                "Server responded to user key request with:\nStatus: {}\nResponse: {}",
                resp.status(),
                resp.text()?
            )));
        }
        // base-64 encoded pem
        let key_response: Key = resp.json()?;
        let key_decoded = BASE64_STANDARD.decode(key_response.key)?;
        let pem = String::from_utf8(key_decoded)?;
        let pkpub = DecodePublicKey::from_public_key_pem(&pem)?;
        pkpubs.push(pkpub);
    }
    // create group for all users
    let group = GroupKey::make_encrypted_group_keys(&pkpubs);
    let members = members
        .members
        .into_iter()
        .zip(group.into_iter())
        .map(|(m, key)| UserWithKey {
            user_email: m.user_email,
            user_id: m.user_id,
            key: BASE64_STANDARD.encode(key),
        })
        .collect();
    let members = GroupMembersWithKey { members };
    let resp = client
        .post(format!(
            "{server_url}/api/v1/group?user_email={email}&user_password_hash={encoded_password}",
        ))
        .json(&members)
        .send()?;
    if !resp.status().is_success() {
        return Err(Box::from(format!(
            "Server responded to group creation request with:\nStatus: {}\nResponse: {}",
            resp.status(),
            resp.text()?
        )));
    }
    let group_id_response: GroupId = resp.json()?;
    Ok(group_id_response.group_id)
}

/// Gets or creates a group on the server and returns the group id
/// Attempts to get the group first, then creates it if it doesn't exist
///
/// # Arguments
///
/// * `server_url` - the url of the server
/// * `email` - the email of the user
/// * `encoded_password` - the base64-encoded password of the user
/// * `ids` - the ids of the users to add to the group
/// * `emails` - the emails of the users to add to the group
/// * `client` - the client to use to make requests
///
/// # Returns
///
/// A `Result` containing the group id
fn get_or_create_group(
    server_url: &str,
    email: &str,
    encoded_password: &str,
    ids: Vec<i64>,
    emails: Vec<String>,
    client: &reqwest::blocking::Client,
) -> Result<i64, Box<dyn Error>> {
    // put emails and ids together
    let mut members = Vec::new();
    for (email, id) in emails.into_iter().zip(ids.iter()) {
        members.push(User {
            user_email: email,
            user_id: *id,
        });
    }
    let members = GroupMembers { members };

    // make request to group endpoint
    let resp = client
        .get(format!(
            "{server_url}/api/v1/group?user_email={email}&user_password_hash={encoded_password}",
        ))
        .json(&members)
        .send()?;
    if resp.status() == StatusCode::NOT_FOUND {
        // group doesn't exist, so create it
        Ok(create_group(
            server_url,
            email,
            encoded_password,
            ids,
            members,
            &client,
        )?)
    } else if resp.status().is_success() {
        // group already exists
        let group_id_response: GroupId = resp.json()?;
        Ok(group_id_response.group_id)
    } else {
        return Err(Box::from(format!(
            "Server responded to group get request with:\nStatus: {}\nResponse: {}",
            resp.status(),
            resp.text()?
        )));
    }
}

/// Uploads a file to the server
///
/// # Arguments
///
/// * `server_url` - the url of the server
/// * `email` - the email of the user
/// * `encoded_password` - the base64-encoded password of the user
/// * `user_id` - the id of the user
/// * `kp` - the keypair of the user
/// * `file` - the file as a stream that implements `Read`
/// * `group_id` - the id of the group to upload the file to, if any.
/// This takes priority over the recipient (email/id) list.
/// * `emails` - the emails of the recipients to send the file to, excluding the current user.
/// * `ids` - the corresponding ids of the recipients to send the file to, excluding the current user.
///
/// # Returns
///
/// * `file_id` - the id of the file that was uploaded
pub fn upload<R: Read>(
    server_url: &str,
    email: &str,
    encoded_password: &str,
    user_id: i64,
    kp: &PkKeyPair,
    mut file: R,
    file_name: &str,
    group_id: Option<i64>,
    mut emails: Vec<String>,
    mut ids: Vec<i64>,
) -> Result<i64, Box<dyn Error>> {
    // file exists and is a valid file, so now need the recipients
    let client = reqwest::blocking::Client::new();
    // get group id and key
    let group_id = match group_id {
        Some(id) => id,
        None => {
            // need to compute it from the given recipients
            if emails.len() != ids.len() {
                return Err(Box::from("Emails and ids must be the same length"));
            }
            // add ourself to the list
            emails.push(email.to_string());
            ids.push(user_id);

            // get group id from server
            get_or_create_group(server_url, email, encoded_password, ids, emails, &client)?
        }
    };

    // so now we have the group id
    // get the group key
    let group_key = get_group_key(server_url, email, encoded_password, group_id, kp, &client)?;

    //trim the server_url's beginning off
    let mut flag = false;
    let url_str_trimmed: String = server_url
        .chars()
        .filter(|x| {
            if *x == ':' {
                flag = true;
            }
            flag
        })
        .collect();

    let url_str = format!(
        "ws{url_str_trimmed}/ws/file-upload?group_id={group_id}&user_email={email}&user_password_hash={encoded_password}"
    );

    let (mut socket, _) = tungstenite::connect(url_str).expect("Can't connect to WebSocket server");

    // send file name
    let file_name_utf8 = Utf8Bytes::from(file_name);

    socket
        .send(Message::Text(file_name_utf8))
        .expect("Failed to send filename");

    // wait for the server's acknowledgement
    match socket.read() {
        Ok(Message::Text(_)) => {}
        _ => {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "Server improperly acknowledged for file upload",
            )));
        }
    }

    let cipher = group_key.get_cipher();

    let fse = FileStreamEncryptor::new(cipher);

    // send nonce_start to the server
    socket
        .send(Message::Binary(Bytes::from_iter(
            fse.get_nonce_start().iter().map(|x| *x),
        )))
        .unwrap();

    let mut buf: [u8; CHUNK_SIZE] = [0; CHUNK_SIZE];
    let mut chunk_ind = 0;

    // read and stream the file, in chunks of CHUNK_SIZE
    loop {
        let mut buf_len = 0;
        while buf_len < CHUNK_SIZE {
            let bytes_read = file.read(&mut buf[buf_len..])?;
            if bytes_read == 0 {
                break; // hit EOF
            }
            buf_len += bytes_read;
        }

        let is_final = buf_len < CHUNK_SIZE;
        let chunk_bytes = &buf[..buf_len];

        let encrypted_chunk = fse
            .encrypt_chunk(&chunk_bytes, chunk_ind, is_final)
            .map_err(|x| x.to_string())?;

        socket.send(Message::Binary(Bytes::from(encrypted_chunk)))?;

        if is_final {
            break;
        }

        chunk_ind += 1;
    }

    socket
        .send(Message::Text(Utf8Bytes::from("finish")))
        .unwrap();
    let file_id_read = socket.read().unwrap().into_data(); //get the file id

    let mut file_id_bytes: [u8; 8] = [0; 8];
    file_id_bytes.copy_from_slice(&file_id_read);
    let file_id = i64::from_be_bytes(file_id_bytes);

    socket.send(Message::Close(None)).unwrap();

    Ok(file_id)
}
