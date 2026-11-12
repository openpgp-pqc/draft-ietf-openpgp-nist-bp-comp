use std::fs::File;
use std::path::Path;
use std::time::SystemTime;

use anyhow::Result;

use sequoia_openpgp as openpgp;

use openpgp::cert::Cert;
use openpgp::crypto::KeyPair;
use openpgp::packet::{
    signature::SignatureBuilder,
    Packet,
    UserID,
};
use openpgp::serialize::Serialize;
use openpgp::types::{
    AEADAlgorithm,
    CompressionAlgorithm,
    Features,
    HashAlgorithm,
    KeyFlags,
    SignatureType,
    SymmetricAlgorithm,
};

use crate::suite::Suite;
use crate::util::{
    ensure_output_dir,
    refuse_existing,
    set_noncritical_creation_time,
    set_noncritical_key_flags,
    TEST_DATA,
};

pub fn generate_all(
    output: &Path,
    force: bool,
) -> Result<()> {
    ensure_output_dir(output)?;

    /*
     * One creation time for the complete generated vector set.
     */
    let creation_time =
        SystemTime::now();

    /*
     * Write the exact test message once.
     */
    let testing =
        output.join("Testing.txt");

    refuse_existing(
        &testing,
        force,
    )?;

    std::fs::write(
        &testing,
        TEST_DATA,
    )?;

    for suite in Suite::ALL {
        generate_one(
            suite,
            creation_time,
            output,
            force,
        )?;
    }

    Ok(())
}

fn generate_one(
    suite: Suite,
    creation_time: SystemTime,
    output: &Path,
    force: bool,
) -> Result<()> {
    let hash =
        suite.certificate_hash();

    let secret_path =
        output.join(
            suite.secret_filename(),
        );

    let public_path =
        output.join(
            suite.public_filename(),
        );

    /*
     * Check before generating any cryptographic material.
     *
     * If one file already exists, don't silently produce a new key
     * set with different fingerprints.
     */
    refuse_existing(
        &secret_path,
        force,
    )?;

    refuse_existing(
        &public_path,
        force,
    )?;

    /*
     * Primary composite signature key.
     */
    let mut primary =
        suite.generate_primary()?;

    primary.set_creation_time(
        creation_time,
    )?;

    let mut signer: KeyPair =
        primary.clone()
            .into_keypair()?;

    /*
     * Direct-key self-signature metadata used by the test vectors:
     *
     *   hash: suite-dependent SHA3-256 or SHA3-512
     *   flags: C,S
     *   features: SEIPDv1, SEIPDv2
     *   AEAD: AES256+OCB, AES192+OCB, AES128+OCB
     *   symmetric: AES256, AES192, AES128
     *   hashes: SHA256, SHA384, SHA512, SHA3-256, SHA3-512
     *   compression: Uncompressed
     */
    let direct =
        SignatureBuilder::new(
            SignatureType::DirectKey,
        )
        .set_hash_algo(hash);

    let direct =
        set_noncritical_creation_time(
            direct,
            creation_time,
        )?;

    let direct =
        direct.set_features(
            Features::empty()
                .set_seipdv1()
                .set_seipdv2(),
        )?;

    let direct =
        set_noncritical_key_flags(
            direct,
            KeyFlags::empty()
                .set_certification()
                .set_signing(),
        )?;

    let direct =
        direct
            .set_preferred_aead_ciphersuites(
                vec![
                    (
                        SymmetricAlgorithm::AES256,
                        AEADAlgorithm::OCB,
                    ),
                    (
                        SymmetricAlgorithm::AES192,
                        AEADAlgorithm::OCB,
                    ),
                    (
                        SymmetricAlgorithm::AES128,
                        AEADAlgorithm::OCB,
                    ),
                ],
            )?
            .set_preferred_symmetric_algorithms(
                vec![
                    SymmetricAlgorithm::AES256,
                    SymmetricAlgorithm::AES192,
                    SymmetricAlgorithm::AES128,
                ],
            )?
            .set_preferred_hash_algorithms(
                vec![
                    HashAlgorithm::SHA256,
                    HashAlgorithm::SHA384,
                    HashAlgorithm::SHA512,
                    HashAlgorithm::SHA3_256,
                    HashAlgorithm::SHA3_512,
                ],
            )?
            .set_preferred_compression_algorithms(
                vec![
                    CompressionAlgorithm::Uncompressed,
                ],
            )?
            .sign_direct_key(
                &mut signer,
                primary.parts_as_public(),
            )?;

    let mut cert =
        Cert::try_from(
            vec![
                Packet::from(
                    primary.clone(),
                ),
                Packet::from(
                    direct,
                ),
            ],
        )?;

    /*
     * Test-vector User ID.
     */
    let userid =
        UserID::from(
            "PQC user (Test Key) <pqc-test-key@example.com>",
        );

    /*
     * Positive-certification self-signature used by the test vectors.
     */
    let userid_sig =
        SignatureBuilder::new(
            SignatureType::PositiveCertification,
        )
        .set_hash_algo(hash);

    let userid_sig =
        set_noncritical_creation_time(
            userid_sig,
            creation_time,
        )?;

    let userid_sig =
        userid_sig
            .sign_userid_binding(
                &mut signer,
                cert.primary_key().key(),
                &userid,
            )?;

    cert =
        cert.insert_packets(
            vec![
                Packet::from(userid),
                Packet::from(userid_sig),
            ],
        )?.0;

    /*
     * Single composite KEM encryption subkey.
     */
    let mut subkey =
        suite.generate_subkey()?;

    subkey.set_creation_time(
        creation_time,
    )?;

    /*
     * Subkey binding used by the test vectors:
     *
     *   hash: suite-dependent SHA3-256 or SHA3-512
     *   flags: Et,Er
     */
    let subkey_binding =
        SignatureBuilder::new(
            SignatureType::SubkeyBinding,
        )
        .set_hash_algo(hash);

    let subkey_binding =
        set_noncritical_creation_time(
            subkey_binding,
            creation_time,
        )?;

    let subkey_binding =
        set_noncritical_key_flags(
            subkey_binding,
            KeyFlags::empty()
                .set_transport_encryption()
                .set_storage_encryption(),
        )?;

    let subkey_sig =
        subkey.bind(
            &mut signer,
            &cert,
            subkey_binding,
        )?;

    cert =
        cert.insert_packets(
            vec![
                Packet::from(subkey),
                Packet::from(subkey_sig),
            ],
        )?.0;

    /*
     * Transferable secret key.
     */
    {
        let mut f =
            File::create(
                &secret_path,
            )?;

        cert.as_tsk()
            .armored()
            .serialize(
                &mut f,
            )?;
    }

    /*
     * Transferable public key.
     */
    {
        let mut f =
            File::create(
                &public_path,
            )?;

        cert.armored()
            .serialize(
                &mut f,
            )?;
    }

    println!(
        "{}/{}:",
        suite.primary_alg_id(),
        suite.subkey_alg_id(),
    );

    println!(
        "  primary: {}",
        cert.fingerprint(),
    );

    for ka in cert.keys().subkeys() {
        println!(
            "  subkey:  {}",
            ka.key().fingerprint(),
        );
    }

    Ok(())
}
