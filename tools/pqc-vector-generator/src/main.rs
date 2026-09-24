mod detached;
mod keys;
mod message;
mod suite;
mod util;

use std::path::PathBuf;

use anyhow::Result;
use clap::{
    Parser,
    Subcommand,
};

#[derive(Parser, Debug)]
#[command(
    name = "pqc-vector-generator",
    about = "Generate OpenPGP NIST/Brainpool composite test vectors"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate the four transferable secret/public key pairs.
    GenerateKeys {
        /// Output directory.
        #[arg(long)]
        output: PathBuf,

        /// Replace existing key files.
        #[arg(long)]
        force: bool,
    },

    /// Generate detached signatures using an existing key set.
    GenerateDetached {
        /// Output directory containing the generated key set.
        #[arg(long)]
        output: PathBuf,

        /// Replace existing detached signature files.
        #[arg(long)]
        force: bool,
    },

    /// Generate encrypted-and-signed messages using an existing key set.
    GenerateMessage {
        /// Output directory containing the generated key set.
        #[arg(long)]
        output: PathBuf,

        /// Replace existing encrypted message files.
        #[arg(long)]
        force: bool,
    },

    /// Generate the complete vector set in one run.
    All {
        /// Output directory.
        #[arg(long)]
        output: PathBuf,

        /// Replace an existing vector set.
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let cli =
        Cli::parse();

    match cli.command {
        Command::GenerateKeys {
            output,
            force,
        } => {
            keys::generate_all(
                &output,
                force,
            )?;
        }

        Command::GenerateDetached {
            output,
            force,
        } => {
            detached::generate_all(
                &output,
                force,
            )?;
        }

        Command::GenerateMessage {
            output,
            force,
        } => {
            message::generate_all(
                &output,
                force,
            )?;
        }

        Command::All {
            output,
            force,
        } => {
            println!("Generating key vectors...");
            keys::generate_all(
                &output,
                force,
            )?;

            println!();
            println!("Generating detached signatures...");
            detached::generate_all(
                &output,
                force,
            )?;

            println!();
            println!("Generating encrypted-and-signed messages...");
            message::generate_all(
                &output,
                force,
            )?;

            println!();
            println!(
                "Complete vector set written to {}",
                output.display(),
            );
        }
    }

    Ok(())
}
