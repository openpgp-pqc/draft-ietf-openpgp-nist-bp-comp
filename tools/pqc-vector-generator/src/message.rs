use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{
    bail,
    Context,
    Result,
};

use sequoia_openpgp as openpgp;

use openpgp::cert::Cert;
use openpgp::parse::Parse;
use openpgp::serialize::stream::{
    Armorer,
    Encryptor,
    LiteralWriter,
    Message,
    Recipient,
    Signer,
};
use openpgp::types::{
    AEADAlgorithm,
    Features,
    SymmetricAlgorithm,
};

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

    let message_path =
        output.join(
            suite.message_filename(),
        );

    refuse_existing(
        &message_path,
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
     * Sign directly with the composite signature primary key.
     *
     * The test-vector certificate deliberately contains no signing
     * subkey.  The only subkey is the composite KEM encryption key.
     */
    let signer =
        cert.primary_key()
            .key()
            .clone()
            .parts_into_secret()?
            .into_keypair()?;

    /*
     * The certificate contains exactly one subordinate key, namely
     * the composite KEM encryption subkey.
     */
    let subkey =
        cert.keys()
            .subkeys()
            .next()
            .context(
                "test-vector certificate has no encryption subkey",
            )?;

    /*
     * Use the v6 subkey fingerprint as the PKESK recipient
     * identifier.
     *
     * Explicitly advertise SEIPDv2 support to the streaming
     * Encryptor.  The generated certificate contains this same
     * feature in its direct-key self-signature.
     */
    let recipient =
        Recipient::new(
            Some(
                Features::empty()
                    .set_seipdv2(),
            ),
            Some(
                subkey
                    .key()
                    .fingerprint()
                    .into(),
            ),
            subkey.key(),
        );

    /*
     * Generate:
     *
     *   ASCII Armor
     *     PKESK v6
     *     SEIPDv2
     *       AES-256
     *       OCB
     *       One-Pass Signature v6
     *       Literal Data ("Testing\n")
     *       Signature v6
     *
     * The embedded message signature uses SHA-256 for all four
     * suites, preserving the convention used by the existing
     * NIST/Brainpool encrypted-and-signed test vectors.
     */
    let mut f =
        File::create(
            &message_path,
        )
        .with_context(|| {
            format!(
                "failed to create {}",
                message_path.display(),
            )
        })?;

    let message =
        Message::new(
            &mut f,
        );

    let message =
        Armorer::new(message)
            .kind(
                openpgp::armor::Kind::Message,
            )
            .build()?;

    let message =
        Encryptor::for_recipients(
            message,
            std::iter::once(recipient),
        )
        .symmetric_algo(
            SymmetricAlgorithm::AES256,
        )
        .aead_algo(
            AEADAlgorithm::OCB,
        )
        .build()?;

    let message =
        Signer::new(
            message,
            signer,
        )?
        .hash_algo(
            suite.encrypted_message_hash(),
        )?
        .build()?;

    let mut message =
        LiteralWriter::new(message)
            .build()?;

    message.write_all(
        TEST_DATA,
    )?;

    message.finalize()?;

    println!(
        "message {}/{}:",
        suite.primary_alg_id(),
        suite.subkey_alg_id(),
    );

    println!(
        "  signature hash: {:?}",
        suite.encrypted_message_hash(),
    );

    println!(
        "  encryption: AES256 + OCB",
    );

    println!(
        "  {}",
        message_path.display(),
    );

    Ok(())
}
