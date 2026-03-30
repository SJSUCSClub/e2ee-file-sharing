use clap::{Parser, Subcommand};
use cli::{download, get_user_info, register, upload};
use rpassword::read_password;
use std::{
    env,
    fs::{self, File},
    io::{self, BufReader, Read, Write},
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
    /// Download and decrypt a file from the server
    Download {
        /// The ID of the file to download
        file_id: i64,
        /// Path to save the file to
        /// If not specified, the file will be saved as the filename provided by the server
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Whether to output to stdout (instead of a file)
        /// Ignored if --output is specified
        #[arg(short, long)]
        stdout: bool,
    },
    /// Encrypt and upload a file to the server
    Upload {
        /// The file to upload
        /// When --stdin is used, this will essentially provide
        /// a name for the file input being piped in
        file: PathBuf,
        /// The ID of the group to upload the file to
        /// This takes priority over the recipient (email/id) list
        #[arg(short, long)]
        group_id: Option<i64>,
        /// The email of the recipients to send the file to
        /// This must be specified if group_id is not
        /// And must be specified along with ids
        #[arg(short, long, value_delimiter = ',')]
        emails: Vec<String>,
        /// The ID of the recipients to send the file to
        /// This must be specified if group_id is not
        /// And must be specified along with emails
        /// The order of the ids must match the order of the emails
        #[arg(short, long, value_delimiter = ',')]
        ids: Vec<i64>,
        /// Whether to use stdin as input
        #[arg(short, long)]
        stdin: bool,
    },
}

// User-facing output should go in stderr, since the user
// can choose to output to stdout when downloading
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

    // get password
    let password = args.password.unwrap_or_else(|| {
        eprint!("Password: ");
        io::stderr().flush().unwrap();
        read_password().unwrap()
    });

    // register is a special case that we need to handle
    // before the others since the user SHOULDN'T exist yet
    if let Subcommands::Register {} = args.command {
        if let Err(e) = register(SERVER_URL, &args.email, &password, disk_key_path) {
            eprintln!("Failed to register: {e}");
        } else {
            eprintln!("Registration successful!");
        }
        return;
    }

    // retrieve kp and validate user by using email and password
    let (kp, encoded_password, user_id) =
        match get_user_info(SERVER_URL, &args.email, &password, disk_key_path) {
            Ok((kp, encoded_password, user_id)) => (kp, encoded_password, user_id),
            Err(e) => {
                eprintln!("Failed to get user info: {e}");
                return;
            }
        };

    // now handle the individual command
    match args.command {
        Subcommands::Download {
            file_id,
            output,
            stdout,
        } => {
            if let Err(e) = download(
                SERVER_URL,
                &args.email,
                &encoded_password,
                &kp,
                file_id,
                output,
                stdout,
            ) {
                eprintln!("Failed to download file: {e}");
            } else {
                eprintln!("Download successful!");
            }
        }
        Subcommands::Upload {
            file,
            group_id,
            emails,
            ids,
            stdin,
        } => {
            let (read_stream, file_name): (Box<dyn Read>, String) = if stdin {
                let stream_in = Box::new(BufReader::new(std::io::stdin()));
                (stream_in, get_file_name_as_string(file))
            } else {
                let tmp = take_file_input(file);
                (Box::new(tmp.0), tmp.1)
            };

            match upload(
                SERVER_URL,
                &args.email,
                &encoded_password,
                user_id,
                &kp,
                read_stream,
                &file_name,
                group_id,
                emails,
                ids,
            ) {
                Ok(file_id) => {
                    eprintln!("Upload successful!");
                    eprintln!("File ID: {file_id}");
                }
                Err(e) => eprintln!("Failed to upload file: {e}"),
            }
        }
        Subcommands::Register {} => unreachable!(),
    }
}

fn take_file_input(file: PathBuf) -> (File, String) {
    match file.try_exists() {
        Ok(exists) => {
            if !exists {
                panic!("File does not exist!");
            }
        }
        Err(e) => {
            panic!("File error: {}", e);
        }
    }
    if !file.is_file() {
        panic!("Not a file!");
    }
    let file_name = file
        .file_name()
        .expect("File name is invalid")
        .to_str()
        .expect("File name is invalid");

    let read_file = std::fs::File::open(&file)
        .map_err(|x| panic!("Couldn't open file: {}", x))
        .unwrap();

    (read_file, file_name.to_string())
}

fn get_file_name_as_string(file: PathBuf) -> String {
    file.file_name().unwrap().to_str().unwrap().to_string()
}
