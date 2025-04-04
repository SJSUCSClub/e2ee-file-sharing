use std::{
    error::Error,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

mod api;
use api::{
    CreateGroupBody, CreateGroupItem, CreateGroupResponse, GetGroupItem, GetGroupKeyResponse,
    GetGroupResponse, GetUserInfoResponse, GetUserKeyResponse, ListFilesItem, UploadFileResponse,
};
use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE, Engine as _};
use corelib::client::{DiskKeys, EncryptedFile, GroupKey, PersonalKey, PkKeyPair};
use reqwest::{StatusCode, blocking::multipart};
use rpassword::read_password;
use rsa::pkcs8::DecodePublicKey;

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
    let info: GetUserInfoResponse = resp.json()?;
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
    print!("Confirm password: ");
    io::stdout().flush()?;
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
    println!("Registering user...");
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
    let info: ListFilesItem = resp.json()?;
    let output_path = match output {
        Some(path) => path,
        None => {
            let result = fs::exists(&info.file_name)?;
            if result {
                return Err(Box::from("File already exists!"));
            } else {
                PathBuf::from(&info.file_name)
            }
        }
    };

    // get group key
    let resp = client
        .get(format!(
            "{server_url}/api/v1/group/{}/key?user_email={email}&user_password_hash={encoded_password}",
            info.group_id,
        ))
        .send()?;
    if !resp.status().is_success() {
        return Err(Box::from(format!(
            "Server responded to group key request with:\nStatus: {}\nResponse: {}",
            resp.status(),
            resp.text()?
        )));
    }
    let group_key_response: GetGroupKeyResponse = resp.json()?;
    let group_key = kp.get_group_key(&group_key_response.encrypted_key);

    // make request to file endpoint
    let resp = client
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

    // decrypt bytes
    let bytes = resp.bytes()?;
    let encrypted_file: EncryptedFile = postcard::from_bytes(&bytes)?;
    let bytes = group_key.decrypt_file(&encrypted_file);

    Ok(fs::write(&output_path, bytes)?)
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
    members: GetGroupResponse,
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
        let key_response: GetUserKeyResponse = resp.json()?;
        let s = String::from_utf8(key_response.key)?;
        let pkpub = DecodePublicKey::from_public_key_pem(&s)?;
        pkpubs.push(pkpub);
    }
    // create group for all users
    let pkpub_refs = pkpubs.iter().collect::<Vec<_>>();
    let group = GroupKey::make_encrypted_group_keys(&pkpub_refs);
    let members = members
        .members
        .into_iter()
        .zip(group.into_iter())
        .map(|(m, key)| CreateGroupItem {
            email: m.email,
            user_id: m.user_id,
            encrypted_key: key,
        })
        .collect();
    let members = CreateGroupBody { members };
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
    let group_id_response: CreateGroupResponse = resp.json()?;
    Ok(group_id_response.group_id)
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
/// * `file` - the path to the file to upload
/// * `group_id` - the id of the group to upload the file to, if any.
/// This takes priority over the recipient (email/id) list.
/// * `emails` - the emails of the recipients to send the file to, excluding the current user.
/// * `ids` - the corresponding ids of the recipients to send the file to, excluding the current user.
///
/// # Returns
///
/// * `file_id` - the id of the file that was uploaded
pub fn upload(
    server_url: &str,
    email: &str,
    encoded_password: &str,
    user_id: i64,
    kp: &PkKeyPair,
    file: PathBuf,
    group_id: Option<i64>,
    mut emails: Vec<String>,
    mut ids: Vec<i64>,
) -> Result<i64, Box<dyn Error>> {
    // first, double check that the file exists
    if !file.try_exists()? {
        return Err(Box::from("File does not exist!"));
    }
    // and that it's a file, not a directory
    if !file.is_file() {
        return Err(Box::from("Not a file!"));
    }

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
            // make request to get group id
            let mut members = Vec::new();
            for (email, id) in emails.into_iter().zip(ids.iter()) {
                members.push(GetGroupItem {
                    email,
                    user_id: *id,
                });
            }
            let members = GetGroupResponse { members };
            let resp = client
                .get(format!(
                    "{server_url}/api/v1/group?user_email={email}&user_password_hash={encoded_password}",
                ))
                .json(&members)
                .send()?;
            if resp.status() == StatusCode::NOT_FOUND {
                // group doesn't exist, so create it
                create_group(server_url, email, encoded_password, ids, members, &client)?
            } else if resp.status().is_success() {
                // group already exists
                let group_id_response: CreateGroupResponse = resp.json()?;
                group_id_response.group_id
            } else {
                return Err(Box::from(format!(
                    "Server responded to group get request with:\nStatus: {}\nResponse: {}",
                    resp.status(),
                    resp.text()?
                )));
            }
        }
    };

    // so now we have the group id
    // get the group key
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
    let group_key_response: GetGroupKeyResponse = resp.json()?;
    let group_key = kp.get_group_key(&group_key_response.encrypted_key);
    // encrypt file
    let bytes = fs::read(&file)?;
    let encrypted_file = group_key.encrypt_file(&bytes);
    // make request to upload endpoint
    let file_part = multipart::Part::bytes(postcard::to_allocvec(&encrypted_file)?)
        .file_name(file.file_name().unwrap().to_str().unwrap().to_string())
        .mime_str("application/octet-stream")?;
    let form = multipart::Form::new().part("file_field", file_part);
    let resp = client
        .post(format!(
            "{server_url}/api/v1/file?group_id={group_id}&user_email={email}&user_password_hash={encoded_password}",
        ))
        .multipart(form)
        .send()?;
    if !resp.status().is_success() {
        return Err(Box::from(format!(
            "Server responded to file upload request with:\nStatus: {}\nResponse: {}",
            resp.status(),
            resp.text()?
        )));
    }

    let result: UploadFileResponse = resp.json()?;
    Ok(result.file_id)
}
