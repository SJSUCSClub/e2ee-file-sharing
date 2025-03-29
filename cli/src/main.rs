use clap::{Parser, Subcommand};
use corelib::client::{DiskKeys, PersonalKey, PkKeyPair};
use rpassword::read_password;
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

    // now handle the individual command
    match args.command {
        _ => todo!(),
    }
}
