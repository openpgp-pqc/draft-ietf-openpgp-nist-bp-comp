use sequoia_openpgp as openpgp;

use openpgp::packet::{
    key::{
        Key6,
        PrimaryRole,
        SecretParts,
        SubordinateRole,
        UnspecifiedRole,
    },
    Key,
};
use openpgp::types::HashAlgorithm;

#[derive(Clone, Copy, Debug)]
pub enum Suite {
    NistP384,
    NistP521,
    BrainpoolP384,
    BrainpoolP512,
}

impl Suite {
    pub const ALL: [Suite; 4] = [
        Suite::NistP384,
        Suite::NistP521,
        Suite::BrainpoolP384,
        Suite::BrainpoolP512,
    ];

    pub fn primary_alg_id(self) -> u8 {
        match self {
            Suite::NistP384 => 41,
            Suite::NistP521 => 42,
            Suite::BrainpoolP384 => 43,
            Suite::BrainpoolP512 => 44,
        }
    }

    pub fn subkey_alg_id(self) -> u8 {
        match self {
            Suite::NistP384 => 37,
            Suite::NistP521 => 38,
            Suite::BrainpoolP384 => 39,
            Suite::BrainpoolP512 => 40,
        }
    }

    /// SHA3-512 for direct-key, User ID, and subkey-binding signatures.
    pub fn certificate_hash(self) -> HashAlgorithm {
        HashAlgorithm::SHA3_512
    }

    /// Message digest for detached signature vectors.
    pub fn detached_hash(self) -> HashAlgorithm {
        match self {
            Suite::NistP384 | Suite::BrainpoolP384 => HashAlgorithm::SHA384,
            Suite::NistP521 | Suite::BrainpoolP512 => HashAlgorithm::SHA3_512,
        }
    }

    /// Message digest for encrypted-and-signed vectors.
    pub fn encrypted_message_hash(self) -> HashAlgorithm {
        match self {
            Suite::NistP384 | Suite::BrainpoolP384 => HashAlgorithm::SHA384,
            Suite::NistP521 | Suite::BrainpoolP512 => HashAlgorithm::SHA3_512,
        }
    }

    pub fn secret_filename(self) -> String {
        format!(
            "seckey-primary{}-sub{}.asc",
            self.primary_alg_id(),
            self.subkey_alg_id(),
        )
    }

    pub fn public_filename(self) -> String {
        format!(
            "pubkey-primary{}-sub{}.asc",
            self.primary_alg_id(),
            self.subkey_alg_id(),
        )
    }

    pub fn detached_filename(self) -> String {
        format!(
            "detached-alg{}.asc",
            self.primary_alg_id(),
        )
    }

    pub fn message_filename(self) -> String {
        format!(
            "encrypted-alg{}_signed-alg{}.asc",
            self.subkey_alg_id(),
            self.primary_alg_id(),
        )
    }

    pub fn generate_primary(
        self,
    ) -> openpgp::Result<
        Key<SecretParts, PrimaryRole>,
    > {
        let key = match self {
            Suite::NistP384 => Key::from(
                Key6::<SecretParts, UnspecifiedRole>::
                    generate_mldsa65_ecdsa_nistp384()?
                    .role_into_primary(),
            ),

            Suite::NistP521 => Key::from(
                Key6::<SecretParts, UnspecifiedRole>::
                    generate_mldsa87_ecdsa_nistp521()?
                    .role_into_primary(),
            ),

            Suite::BrainpoolP384 => Key::from(
                Key6::<SecretParts, UnspecifiedRole>::
                    generate_mldsa65_ecdsa_brainpoolp384()?
                    .role_into_primary(),
            ),

            Suite::BrainpoolP512 => Key::from(
                Key6::<SecretParts, UnspecifiedRole>::
                    generate_mldsa87_ecdsa_brainpoolp512()?
                    .role_into_primary(),
            ),
        };

        Ok(key)
    }

    pub fn generate_subkey(
        self,
    ) -> openpgp::Result<
        Key<SecretParts, SubordinateRole>,
    > {
        let key = match self {
            Suite::NistP384 => Key::from(
                Key6::<SecretParts, UnspecifiedRole>::
                    generate_mlkem768_ecdh_nistp384()?
                    .role_into_subordinate(),
            ),

            Suite::NistP521 => Key::from(
                Key6::<SecretParts, UnspecifiedRole>::
                    generate_mlkem1024_ecdh_nistp521()?
                    .role_into_subordinate(),
            ),

            Suite::BrainpoolP384 => Key::from(
                Key6::<SecretParts, UnspecifiedRole>::
                    generate_mlkem768_ecdh_brainpoolp384()?
                    .role_into_subordinate(),
            ),

            Suite::BrainpoolP512 => Key::from(
                Key6::<SecretParts, UnspecifiedRole>::
                    generate_mlkem1024_ecdh_brainpoolp512()?
                    .role_into_subordinate(),
            ),
        };

        Ok(key)
    }
}
