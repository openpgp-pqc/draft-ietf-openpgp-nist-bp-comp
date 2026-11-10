mod detached;
mod keys;
mod message;
mod suite;
mod util;
mod verify;

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

    /// Primary algorithm IDs to process (repeat for multiple suites).
    #[arg(long, global = true, value_parser = clap::value_parser!(u8).range(41..=44))]
    suite: Vec<u8>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify signatures, plaintext, and packet parameters with Sequoia.
    Verify {
        #[arg(long)]
        output: PathBuf,
        /// Check the draft text against the verified artifacts and metadata.
        #[arg(long)]
        draft: Option<PathBuf>,
    },
    /// Generate the four transferable secret/public key pairs.
    GenerateKeys {
        /// Output directory.
        #[arg(long)]
        output: PathBuf,

        /// Re-sign existing key packets, preserving their fingerprints.
        #[arg(long, requires = "force")]
        reuse_keys: bool,

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

    let suites: Vec<_> = suite::Suite::ALL.into_iter()
        .filter(|s| cli.suite.is_empty() || cli.suite.contains(&s.primary_alg_id()))
        .collect();

    match cli.command {
        Command::Verify { output, draft } => verify::verify_all(&suites, &output, draft.as_deref())?,
        Command::GenerateKeys {
            output,
            force,
            reuse_keys,
        } => {
            keys::generate_all(
                &suites,
                &output,
                force,
                reuse_keys,
            )?;
        }

        Command::GenerateDetached {
            output,
            force,
        } => {
            detached::generate_all(
                &suites,
                &output,
                force,
            )?;
        }

        Command::GenerateMessage {
            output,
            force,
        } => {
            message::generate_all(
                &suites,
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
                &suites,
                &output,
                force,
                false,
            )?;

            println!();
            println!("Generating detached signatures...");
            detached::generate_all(
                &suites,
                &output,
                force,
            )?;

            println!();
            println!("Generating encrypted-and-signed messages...");
            message::generate_all(
                &suites,
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
