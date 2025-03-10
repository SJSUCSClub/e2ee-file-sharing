use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
struct Cli {
    /// Username to authenticate with.
    #[arg(short, long)]
    name: String,
    /// Password to authenticate with.
    /// If unspecified, interactively prompts for the password.
    #[arg(short, long)]
    password: Option<String>,

    #[command(subcommand)]
    command: Option<Subcommands>,
}

#[derive(Subcommand)]
enum Subcommands {
    /// Register a new account with the provided username and password credentials.
    Register {},
    /// Send a file to a list of recipients.
    Send {
        recipients: Vec<String>,
        file: PathBuf,
    },
}

fn main() {
    let args = Cli::parse();
}
