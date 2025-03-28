use base64::prelude::{BASE64_URL_SAFE, Engine as _};
use clap::{Parser, Subcommand};
use corelib::client::{DiskKeys, EncryptedFile, PersonalKey, PkKeyPair};
use rpassword::read_password;
use serde::Deserialize;
use std::{
    env, fs,
    io::{self, Write},
    path::PathBuf,
};

const SERVER_URL: &str = "http://localhost:8000";

#[derive(Parser, Debug)]
struct Cli {
    /// Email to authenticate with.
    #[arg(short, long)]
    email: String,
    /// Password to authenticate with.
    /// If unspecified, interactively prompts for the password.
    #[arg(short, long)]
    password: Option<String>,

    #[command(subcommand)]
    command: Subcommands,
}

#[derive(Subcommand, Debug)]
enum Subcommands {
    /// Register a new account with the provided email and password credentials.
    Register {},
    /// Send a file to a list of recipients.
    Send {
        recipients: Vec<String>,
        file: PathBuf,
    },
    /// Download and decrypt a file from the server
    Download {
        /// The ID of the file to download
        #[arg(short, long)]
        file_id: i64,
        /// Path to save the file to
        /// If not specified, the file will be saved as the filename provided by the server
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

// ==============================
// Request and response structs
// ==============================
/// Response from the server containing file information
#[derive(Deserialize, Debug)]
struct FileInfoResponse {
    file_name: String,
    file_id: i64,
    group_name: String,
    group_id: i64,
}

#[derive(Deserialize, Debug)]
struct GetGroupKeyResponse {
    encrypted_key: Vec<u8>,
}

fn main() {
    let args = Cli::parse();

    // get disk key path
    // according to https://specifications.freedesktop.org/basedir-spec/latest/,
    // we want to start with $XDG_DATA_HOME
    // and if that doesn't work, fall back to $HOME/.local/share
    // else fall back to $HOME
    let disk_key_path_buf = if let Ok(xdg) = env::var("XDG_DATA_HOME") {
        PathBuf::from(xdg).join("e2ee-file-sharing")
    } else {
        // even though home_dir is still marked as deprecated in 1.85,
        // the docs say that it's actually fine and will be un-deprecated in 1.86
        // https://crates.io/crates/home
        #[allow(deprecated)]
        let home = env::home_dir().expect("Inaccessible");
        let local_share = home.join(".local/share");
        if fs::exists(&local_share).unwrap_or(false) {
            local_share.join("e2ee-file-sharing")
        } else {
            home.join(".e2ee-file-sharing")
        }
    };
    let disk_key_path = disk_key_path_buf.as_path();

    // create directory if it doesn't exist
    std::fs::create_dir_all(disk_key_path).expect("Inaccessible");

    let password = args.password.unwrap_or_else(|| {
        print!("Password: ");
        io::stdout().flush().unwrap();
        read_password().unwrap()
    });

    // register, which may do stuff
    if let Subcommands::Register {} = args.command {
        // confirm password
        print!("Confirm password: ");
        io::stdout().flush().unwrap();
        let confirm = read_password().unwrap();
        if password != confirm {
            println!("Passwords do not match!");
            return;
        }
        // passwords match
        // first, check if we already have a key
        if fs::exists(disk_key_path.join(&args.email)).expect("Inaccessible") {
            println!("User disk key already exists!");
            println!(
                "Please remove this file to register a user with the provided email, or use a different email."
            );
            return;
        }

        // no key, so let's create one
        // create our personal_key and keypair
        let personal_key = PersonalKey::derive(&args.email, &password);
        let kp = PkKeyPair::new();
        let pk_pub = kp
            .get_public_key_pem()
            .expect("unable to extract public key");
        let keys = DiskKeys::new(&personal_key, &kp);

        // send registration request
        let client = reqwest::blocking::Client::new();
        let json = serde_json::json!({
            "email": args.email,
            "key_hash": personal_key.hash(),
            "public_key": pk_pub
        });
        let json = serde_json::to_string(&json).unwrap();
        let req = client
            .post(SERVER_URL.to_string() + "/register")
            .body(json)
            .send()
            .expect("Failed to send registration request");
        if !req.status().is_success() {
            println!("Registration failed!");
            println!(
                "Error: {}",
                String::from_utf8(req.bytes().unwrap().to_vec()).unwrap()
            );
            return;
        }

        // encrypt and store
        // choice of postcard because it does well on benchmarks:
        // https://github.com/djkoloski/rust_serialization_benchmark
        let bytes = postcard::to_stdvec(&keys).unwrap().to_vec();
        fs::write(disk_key_path.join(&args.email), bytes).expect("Inaccessible");
        println!("Registration successful!");
        return;
    }

    // look in storage to recover our kp and key hash
    let bytes = fs::read(disk_key_path.join(&args.email)).expect("Failed to find disk keys!");
    let keys: DiskKeys = postcard::from_bytes(bytes.as_slice()).unwrap();
    let personal_key = PersonalKey::derive(&args.email, &password);
    let kp = keys.to_memory(&personal_key);
    let encoded_password = BASE64_URL_SAFE.encode(personal_key.hash().to_vec());
    println!("Encoded keypair is: {}", encoded_password);

    // now handle the individual command
    match args.command {
        Subcommands::Download { file_id, output } => {
            let client = reqwest::blocking::Client::new();
            // make request to file info endpoint
            let resp = client
                .get(format!(
                    "{SERVER_URL}/api/v1/file/{file_id}/info?user_email={}&user_password_hash={}",
                    args.email, encoded_password
                ))
                .send()
                .unwrap();
            if !resp.status().is_success() {
                println!("Failed to get file info!");
                println!("Status code: {}", resp.status());
                println!(
                    "Error: {}",
                    String::from_utf8(resp.bytes().unwrap().to_vec()).unwrap()
                );
                return;
            }
            // parse the response
            let info: FileInfoResponse = resp.json().unwrap();
            println!("Info: {info:#?}");

            let output_path = output.unwrap_or_else(|| {
                let result = fs::exists(&info.file_name).expect("Inaccessible");
                if result {
                    panic!("File already exists!");
                } else {
                    PathBuf::from(&info.file_name)
                }
            });

            // get group key
            let resp = client
                .get(format!(
                    "{SERVER_URL}/api/v1/group/{}/key?user_email={}&user_password_hash={}",
                    info.group_id, args.email, encoded_password
                ))
                .send()
                .unwrap();
            if !resp.status().is_success() {
                println!("Failed to get group key!");
                println!("Status code: {}", resp.status());
                println!(
                    "Error: {}",
                    String::from_utf8(resp.bytes().unwrap().to_vec()).unwrap()
                );
                return;
            }
            let group_key_response: GetGroupKeyResponse = resp.json().unwrap();
            let group_key = kp.get_group_key(&group_key_response.encrypted_key);

            // make request to file endpoint
            let resp = client
                .get(format!(
                    "{SERVER_URL}/api/v1/file?file_id={file_id}&user_email={}&user_password_hash={}",
                    args.email,
                    encoded_password
                ))
                .send()
                .unwrap();
            if !resp.status().is_success() {
                println!("Failed to get file!");
                println!("Status code: {}", resp.status());
                println!(
                    "Error: {}",
                    String::from_utf8(resp.bytes().unwrap().to_vec()).unwrap()
                );
                return;
            }
            // decrypt bytes
            let bytes = resp.bytes().unwrap();
            let encrypted_file: EncryptedFile = postcard::from_bytes(&bytes).unwrap();
            let bytes = group_key.decrypt_file(&encrypted_file);

            let mut file = fs::File::create(&output_path).expect("Inaccessible");
            file.write_all(&bytes).unwrap();
            println!("Downloaded!");
        }
        _ => todo!(),
    }
}
