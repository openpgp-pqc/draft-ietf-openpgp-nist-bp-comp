//! Verification of the published vectors using the configured Sequoia backend.
use crate::{suite::Suite, util::TEST_DATA};
use anyhow::{Context, Result, ensure};
use openpgp::crypto::SessionKey;
use openpgp::parse::stream::{
    DecryptionHelper, DecryptorBuilder, DetachedVerifierBuilder, MessageLayer, MessageStructure,
    VerificationHelper,
};
use openpgp::parse::{PacketParser, Parse};
use openpgp::policy::NullPolicy;
use openpgp::types::{AEADAlgorithm, HashAlgorithm, SymmetricAlgorithm, SignatureType};
use openpgp::{Cert, KeyHandle, Packet, PacketPile};
use sequoia_openpgp as openpgp;
use std::{io::Read, path::Path};

struct Helper {
    public: Cert,
    secret: Cert,
    hash: HashAlgorithm,
    primary: u8,
    subkey: u8,
    packets: Vec<&'static str>,
    session_key: Option<String>,
}

impl VerificationHelper for Helper {
    fn get_certs(&mut self, _: &[KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(vec![self.public.clone()])
    }

    fn inspect(&mut self, pp: &PacketParser) -> openpgp::Result<()> {
        match &pp.packet {
            Packet::PKESK(p) => {
                ensure!(
                    p.version() == 6 && u8::from(p.pk_algo()) == self.subkey,
                    "wrong PKESK"
                );
                let key = self
                    .secret
                    .keys()
                    .subkeys()
                    .next()
                    .context("missing subkey")?;
                ensure!(
                    p.recipient() == Some(key.key().fingerprint().into()),
                    "wrong recipient"
                );
                self.packets.push("PKESK");
            }
            Packet::SEIP(openpgp::packet::SEIP::V2(p)) => {
                ensure!(
                    p.symmetric_algo() == SymmetricAlgorithm::AES256
                        && p.aead() == AEADAlgorithm::OCB
                        && p.chunk_size() == 4096,
                    "wrong SEIPDv2 parameters"
                );
                self.packets.push("SEIPD");
            }
            Packet::OnePassSig(p) => {
                ensure!(
                    p.version() == 6
                        && p.hash_algo() == self.hash
                        && u8::from(p.pk_algo()) == self.primary,
                    "wrong one-pass signature"
                );
                self.packets.push("OPS");
            }
            Packet::Literal(_) => self.packets.push("Literal"),
            Packet::Signature(p) => {
                ensure!(
                    p.version() == 6
                        && p.hash_algo() == self.hash
                        && u8::from(p.pk_algo()) == self.primary,
                    "wrong signature parameters"
                );
                self.packets.push("Signature");
            }
            p => anyhow::bail!("unexpected packet: {:?}", p.tag()),
        }
        Ok(())
    }

    fn check(&mut self, structure: MessageStructure) -> openpgp::Result<()> {
        let mut count = 0;
        for layer in structure.iter() {
            if let MessageLayer::SignatureGroup { results } = layer {
                for result in results {
                    let good = result
                        .as_ref()
                        .map_err(|e| anyhow::anyhow!("bad signature: {e}"))?;
                    ensure!(good.sig.hash_algo() == self.hash, "wrong message digest");
                    ensure!(
                        good.ka.key().fingerprint() == self.public.fingerprint(),
                        "wrong signer"
                    );
                    count += 1;
                }
            }
        }
        ensure!(
            count == 1,
            "expected exactly one valid signature, got {count}"
        );
        Ok(())
    }
}

impl DecryptionHelper for Helper {
    fn decrypt(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        skesks: &[openpgp::packet::SKESK],
        sym: Option<SymmetricAlgorithm>,
        decrypt: &mut dyn FnMut(Option<SymmetricAlgorithm>, &SessionKey) -> bool,
    ) -> openpgp::Result<Option<Cert>> {
        ensure!(
            pkesks.len() == 1 && skesks.is_empty(),
            "unexpected recipients"
        );
        let mut key = self
            .secret
            .keys()
            .subkeys()
            .next()
            .context("missing subkey")?
            .key()
            .clone()
            .parts_into_secret()?
            .into_keypair()?;
        let (algo, session) = pkesks[0]
            .decrypt(&mut key, sym)
            .context("PKESK decryption failed")?;
        self.session_key = Some(openpgp::fmt::hex::encode(&session));
        ensure!(decrypt(algo, &session), "payload decryption failed");
        Ok(Some(self.secret.clone()))
    }
}

fn check_certificate(path: &Path, suite: Suite) -> Result<Cert> {
    // Inspect raw packets before Cert canonicalization can discard bad signatures.
    let pile = PacketPile::from_file(path)?;
    let cert = Cert::from_file(path)?;
    let primary = cert.primary_key().key();
    let userid = cert.userids().next().context("missing User ID")?;
    let subkey = cert.keys().subkeys().next().context("missing subkey")?;
    let mut kinds = Vec::new();
    for packet in pile.descendants() {
        if let Packet::Signature(sig) = packet {
            ensure!(
                matches!(sig.hash_algo(), HashAlgorithm::SHA384
                    | HashAlgorithm::SHA512 | HashAlgorithm::SHA3_512),
                "certificate signature digest below 384 bits or unsupported in {}",
                path.display()
            );
            ensure!(sig.hash_algo() == suite.certificate_hash(),
                "unexpected certificate signature hash in {}", path.display());
            ensure!(sig.version() == 6 && u8::from(sig.pk_algo()) == suite.primary_alg_id(),
                "wrong certificate signature parameters");
            match sig.typ() {
                SignatureType::DirectKey => {
                    sig.verify_direct_key(primary, primary)?;
                    ensure!(sig.preferred_hash_algorithms() == Some(&[
                        HashAlgorithm::SHA384, HashAlgorithm::SHA512,
                        HashAlgorithm::SHA3_512,
                    ][..]), "wrong certificate hash preferences");
                }
                SignatureType::PositiveCertification =>
                    sig.verify_userid_binding(primary, primary, userid.userid())?,
                SignatureType::SubkeyBinding =>
                    sig.verify_subkey_binding(primary, primary, subkey.key())?,
                _ => anyhow::bail!("unexpected certificate signature type"),
            }
            kinds.push(sig.typ());
        }
    }
    ensure!(kinds == [SignatureType::DirectKey,
        SignatureType::PositiveCertification, SignatureType::SubkeyBinding],
        "wrong certificate signature sequence");
    Ok(cert)
}

pub fn verify_all(suites: &[Suite], output: &Path, draft: Option<&Path>) -> Result<()> {
    let draft = draft.map(std::fs::read_to_string).transpose()?;
    // This checks fixed test artifacts with assigned composite algorithm IDs.
    // Certificate signatures are checked explicitly before using NullPolicy.
    // Cryptographic checks and exact algorithm/packet assertions remain enabled.
    let policy = unsafe { NullPolicy::new() };
    ensure!(
        std::fs::read(output.join("Testing.txt"))? == TEST_DATA,
        "wrong test payload"
    );
    for &suite in suites {
        let public = check_certificate(&output.join(suite.public_filename()), suite)?;
        let secret = check_certificate(&output.join(suite.secret_filename()), suite)?;
        ensure!(
            public.fingerprint() == secret.fingerprint(),
            "certificate mismatch"
        );
        let helper = |hash| Helper {
            public: public.clone(),
            secret: secret.clone(),
            hash,
            primary: suite.primary_alg_id(),
            subkey: suite.subkey_alg_id(),
            packets: Vec::new(),
            session_key: None,
        };
        let mut verifier =
            DetachedVerifierBuilder::from_file(output.join(suite.detached_filename()))?
                .with_policy(&policy, None, helper(suite.detached_hash()))?;
        verifier.verify_bytes(TEST_DATA)?;
        let mut decryptor = DecryptorBuilder::from_file(output.join(suite.message_filename()))?
            .with_policy(&policy, None, helper(suite.encrypted_message_hash()))?;
        let mut plaintext = Vec::new();
        decryptor.read_to_end(&mut plaintext)?;
        ensure!(plaintext == TEST_DATA, "incorrect plaintext");
        let h = decryptor.into_helper();
        ensure!(
            h.packets == ["PKESK", "SEIPD", "OPS", "Literal", "Signature"],
            "unexpected message packet sequence: {:?}",
            h.packets
        );
        let metadata_path = output.join(format!("metadata-alg{}.json", suite.primary_alg_id()));
        ensure!(
            draft.is_none() || metadata_path.exists(),
            "draft checks require metadata"
        );
        if metadata_path.exists() {
            let metadata: serde_json::Value =
                serde_json::from_slice(&std::fs::read(metadata_path)?)?;
            ensure!(
                metadata["sessionKey"].as_str() == h.session_key.as_deref(),
                "metadata session key mismatch"
            );
            if let Some(draft) = &draft {
                check_draft(draft, suite, &public, &metadata)?;
            }
        }
        println!(
            "suite {}/{}: certificates, signatures, hashes, recipient, AES256/OCB, chunk size, plaintext OK",
            suite.primary_alg_id(),
            suite.subkey_alg_id()
        );
    }
    Ok(())
}

/// Check the statements within each suite's own section, rather than searching
/// the whole document where another vector could hide a missing statement.
fn check_draft(draft: &str, suite: Suite, cert: &Cert, metadata: &serde_json::Value) -> Result<()> {
    let number = usize::from(suite.primary_alg_id() - 40);
    let marker = format!("### Transferable Secret Key {{#test-vector-{number}-sec}}");
    let section = draft
        .split_once(&marker)
        .context("missing draft suite section")?
        .1;
    let section = section.split("\n## ").next().unwrap();
    let (keys, messages) = section
        .split_once("### Encrypted and Signed Message")
        .context("missing encrypted message section")?;
    let (encrypted, detached) = messages
        .split_once("### Detached Signature")
        .context("missing detached signature section")?;
    let secret_section = keys.split("### Transferable Public Key").next().unwrap();
    ensure!(secret_section.matches("All self-signatures use ").count() == 1
        && secret_section.contains("All self-signatures use SHA3-512 as their hash algorithm."),
        "draft certificate digest statement missing or incorrect");
    let primary = cert.fingerprint().to_string();
    let subkey = cert
        .keys()
        .subkeys()
        .next()
        .context("missing subkey")?
        .key()
        .fingerprint()
        .to_string();
    for (label, value) in [("primary key", &primary), ("subkey", &subkey)] {
        ensure!(
            keys.contains(&format!("The {label} has the fingerprint\n`{value}`.")),
            "draft {label} fingerprint mismatch for suite {}",
            suite.primary_alg_id()
        );
    }
    ensure!(
        metadata["recipient"].as_str() == Some(subkey.as_str()),
        "metadata recipient mismatch"
    );
    for (field, phrase) in [
        (
            "mlkemKeyShare",
            "The hex-encoded `mlkemKeyShare` input to `multiKeyCombine` is",
        ),
        (
            "ecdhKeyShare",
            "The hex-encoded `ecdhKeyShare` input to `multiKeyCombine` is",
        ),
        (
            "multiKeyCombine",
            "The hex-encoded output of `multiKeyCombine` is",
        ),
        ("sessionKey", "The hex-encoded session key is"),
    ] {
        let value = metadata[field].as_str().context("missing metadata value")?;
        ensure!(
            encrypted.contains(&format!("{phrase} `{value}`.")),
            "draft {field} mismatch for suite {}",
            suite.primary_alg_id()
        );
    }
    for (name, text, hash) in [
        ("encrypted", encrypted, suite.encrypted_message_hash()),
        ("detached", detached, suite.detached_hash()),
    ] {
        let hash = match hash {
            HashAlgorithm::SHA384 => "SHA2-384",
            HashAlgorithm::SHA3_512 => "SHA3-512",
            _ => anyhow::bail!("unexpected vector digest"),
        };
        let statement = format!("The signature uses {hash} as its hash algorithm.");
        ensure!(
            text.matches("The signature uses ").count() == 1 && text.contains(&statement),
            "draft {name} digest statement missing or incorrect for suite {}",
            suite.primary_alg_id()
        );
    }
    println!(
        "suite {}: draft fingerprints, KEM values, and digest statements OK",
        suite.primary_alg_id()
    );
    Ok(())
}
