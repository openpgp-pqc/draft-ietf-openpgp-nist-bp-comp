use std::fs::File;
use std::path::Path;

use anyhow::{
    bail,
    Context,
    Result,
};

use sequoia_openpgp as openpgp;

use openpgp::cert::Cert;
use openpgp::parse::Parse;
use openpgp::packet::signature::SignatureBuilder;
use openpgp::serialize::Serialize;
use openpgp::serialize::stream::{
    Armorer,
    Message,
};
use openpgp::types::SignatureType;

use crate::suite::Suite;
use crate::util::{
    ensure_output_dir,
    refuse_existing,
    TEST_DATA,
};

pub fn generate_all(
    output: &Path,
    force: bool,
) -> Result<()> {
    ensure_output_dir(output)?;

    let testing_path =
        output.join("Testing.txt");

    if !testing_path.exists() {
        bail!(
            "{} does not exist; run generate-keys first",
            testing_path.display(),
        );
    }

    let testing =
        std::fs::read(&testing_path)
            .with_context(|| {
                format!(
                    "failed to read {}",
                    testing_path.display(),
                )
            })?;

    if testing != TEST_DATA {
        bail!(
            "{} does not contain the expected test data",
            testing_path.display(),
        );
    }

    for suite in Suite::ALL {
        generate_one(
            suite,
            output,
            force,
        )?;
    }

    Ok(())
}

fn generate_one(
    suite: Suite,
    output: &Path,
    force: bool,
) -> Result<()> {
    let secret_path =
        output.join(
            suite.secret_filename(),
        );

    if !secret_path.exists() {
        bail!(
            "{} does not exist; run generate-keys first",
            secret_path.display(),
        );
    }

    let detached_path =
        output.join(
            suite.detached_filename(),
        );

    refuse_existing(
        &detached_path,
        force,
    )?;

    let cert =
        Cert::from_file(
            &secret_path,
        )
        .with_context(|| {
            format!(
                "failed to parse {}",
                secret_path.display(),
            )
        })?;

    /*
     * The test-vector certificates use their primary key for signing.
     */
    let mut signer =
        cert.primary_key()
            .key()
            .clone()
            .parts_into_secret()?
            .into_keypair()?;

    /*
     * Detached signature over the exact test-vector payload:
     *
     *     Testing\n
     *
     * The hash follows the corresponding RFC 9980 test-vector
     * pattern:
     *
     *   ML-DSA-65 -> SHA-256
     *   ML-DSA-87 -> SHA3-512
     *
     * SignatureBuilder's normal v6 behavior is used for the
     * signature creation-time subpacket.
     */
    let signature =
        SignatureBuilder::new(
            SignatureType::Binary,
        )
        .set_hash_algo(
            suite.detached_hash(),
        )
        .sign_message(
            &mut signer,
            TEST_DATA,
        )?;

    /*
     * Serialize the detached Signature packet using ASCII armor.
     */
    let mut f =
        File::create(
            &detached_path,
        )
        .with_context(|| {
            format!(
                "failed to create {}",
                detached_path.display(),
            )
        })?;

    let message =
        Message::new(
            &mut f,
        );

    let mut message =
        Armorer::new(message)
            .kind(
                openpgp::armor::Kind::Signature,
            )
            .build()?;

    openpgp::Packet::from(signature)
        .serialize(
            &mut message,
        )?;

    message.finalize()?;

    println!(
        "detached {}:",
        suite.primary_alg_id(),
    );

    println!(
        "  hash: {:?}",
        suite.detached_hash(),
    );

    println!(
        "  {}",
        detached_path.display(),
    );

    Ok(())
}
