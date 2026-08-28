use std::path::Path;
use std::time::SystemTime;

use anyhow::{
    bail,
    Result,
};

use sequoia_openpgp as openpgp;

use openpgp::packet::signature::{
    subpacket::{
        Subpacket,
        SubpacketValue,
    },
    SignatureBuilder,
};
use openpgp::types::KeyFlags;

pub const TEST_DATA: &[u8] = b"Testing\n";

pub fn ensure_output_dir(
    output: &Path,
) -> Result<()> {
    std::fs::create_dir_all(output)?;
    Ok(())
}

pub fn refuse_existing(
    path: &Path,
    force: bool,
) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; refusing to overwrite it without --force",
            path.display(),
        );
    }

    Ok(())
}

pub fn set_noncritical_creation_time(
    builder: SignatureBuilder,
    creation_time: SystemTime,
) -> Result<SignatureBuilder> {
    /*
     * First use Sequoia's setter so the builder records that the
     * creation time was explicitly supplied.
     */
    let builder =
        builder.set_signature_creation_time(
            creation_time,
        )?;

    /*
     * Reinsert the same subpacket without the critical bit, matching
     * the certificate metadata used by the test vectors.
     */
    Ok(builder.modify_hashed_area(
        |mut area| {
            area.replace(
                Subpacket::new(
                    SubpacketValue::SignatureCreationTime(
                        creation_time.try_into()?,
                    ),
                    false,
                )?,
            )?;

            Ok(area)
        },
    )?)
}

pub fn set_noncritical_key_flags(
    builder: SignatureBuilder,
    flags: KeyFlags,
) -> Result<SignatureBuilder> {
    let builder =
        builder.set_key_flags(
            flags.clone(),
        )?;

    Ok(builder.modify_hashed_area(
        |mut area| {
            area.replace(
                Subpacket::new(
                    SubpacketValue::KeyFlags(flags),
                    false,
                )?,
            )?;

            Ok(area)
        },
    )?)
}
