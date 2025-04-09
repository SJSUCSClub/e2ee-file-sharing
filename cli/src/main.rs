use clap::{Parser, Subcommand, ValueEnum};
use cli::{download, get_user_info, list_files, register, upload};
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
    /// List all files associated with this account
    List {
        /// Output Format
        #[arg(long, value_enum, default_value_t = OutputFormat::Plain)]
        output_format: OutputFormat,
    },
    /// Download and decrypt a file from the server
    Download {
        /// The ID of the file to download
        file_id: i64,
        /// Path to save the file to
        /// If not specified, the file will be saved as the filename provided by the server
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Encrypt and upload a file to the server
    Upload {
        /// The file to upload
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
    },
}

#[derive(Copy, Clone, PartialEq, PartialOrd, Eq, Ord, ValueEnum, Debug)]
enum OutputFormat {
    Plain,
    Csv,
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

    // get password
    let password = args.password.unwrap_or_else(|| {
        print!("Password: ");
        io::stdout().flush().unwrap();
        read_password().unwrap()
    });

    // register is a special case that we need to handle
    // before the others since the user SHOULDN'T exist yet
    if let Subcommands::Register {} = args.command {
        if let Err(e) = register(SERVER_URL, &args.email, &password, disk_key_path) {
            println!("Failed to register: {e}");
        } else {
            println!("Registration successful!");
        }
        return;
    }

    // retrieve kp and validate user by using email and password
    let (kp, encoded_password, user_id) =
        match get_user_info(SERVER_URL, &args.email, &password, disk_key_path) {
            Ok((kp, encoded_password, user_id)) => (kp, encoded_password, user_id),
            Err(e) => {
                println!("Failed to get user info: {e}");
                return;
            }
        };

    // now handle the individual command
    match args.command {
        Subcommands::Download { file_id, output } => {
            if let Err(e) = download(
                SERVER_URL,
                &args.email,
                &encoded_password,
                &kp,
                file_id,
                output,
            ) {
                println!("Failed to download file: {e}");
            } else {
                println!("Download successful!");
            }
        }
        Subcommands::Upload {
            file,
            group_id,
            emails,
            ids,
        } => {
            match upload(
                SERVER_URL,
                &args.email,
                &encoded_password,
                user_id,
                &kp,
                file,
                group_id,
                emails,
                ids,
            ) {
                Ok(file_id) => {
                    println!("Upload successful!");
                    println!("File ID: {file_id}");
                }
                Err(e) => println!("Failed to upload file: {e}"),
            }
        }
        Subcommands::List { output_format } => {
            match list_files(SERVER_URL, &args.email, &encoded_password) {
                Ok(file_infos) => {
                    match output_format {
                        OutputFormat::Plain => {
                            println!(
                                "{:<20} {:<10} {:<15} {:<10}",
                                "file_name", "file_id", "group_name", "group_id"
                            );
                            println!("{}", "-".repeat(60));

                            // Print each file info
                            for file in file_infos.files {
                                println!(
                                    "{:<20} {:<10} {:<15} {:<10}",
                                    file.file_name, file.file_id, file.group_name, file.group_id
                                );
                            }
                        }
                        OutputFormat::Csv => {
                            println!("file_name, file_id, group_name, group_id");
                            // Print each file info
                            for file in file_infos.files {
                                println!(
                                    "{},{},{},{}",
                                    file.file_name, file.file_id, file.group_name, file.group_id
                                );
                            }
                        }
                    }
                }
                Err(e) => println!("Failed to list files: {e}"),
            }
        }
        Subcommands::Register {} => unreachable!(),
    }
}
