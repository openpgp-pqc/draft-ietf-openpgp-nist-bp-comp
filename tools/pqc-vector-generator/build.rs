//! Reject the old private-ID checkout before running vector generation.
use std::{env, fs, path::PathBuf};

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let cargo = fs::read_to_string(manifest.join("Cargo.toml")).unwrap();
    let dependency = cargo
        .split("[dependencies.sequoia-openpgp]")
        .nth(1)
        .expect("missing Sequoia dependency table");
    let path = dependency
        .lines()
        .find_map(|line| line.trim().strip_prefix("path = "))
        .expect("missing Sequoia path")
        .trim_matches('"');
    let source = manifest
        .join(path)
        .join("src/crypto/types/public_key_algorithm.rs");
    println!("cargo:rerun-if-changed={}", source.display());
    println!("cargo:rerun-if-changed=Cargo.toml");
    let mappings = fs::read_to_string(&source).unwrap_or_default();
    let mappings: String = mappings.chars().filter(|c| !c.is_whitespace()).collect();
    for (id, variant) in [
        (37, "MLKEM768_ECDH_NISTP384"),
        (38, "MLKEM1024_ECDH_NISTP521"),
        (39, "MLKEM768_ECDH_BrainpoolP384"),
        (40, "MLKEM1024_ECDH_BrainpoolP512"),
        (41, "MLDSA65_ECDSA_NISTP384"),
        (42, "MLDSA87_ECDSA_NISTP521"),
        (43, "MLDSA65_ECDSA_BrainpoolP384"),
        (44, "MLDSA87_ECDSA_BrainpoolP512"),
    ] {
        assert!(
            mappings.contains(&format!("{id}=>{variant},"))
                && mappings.contains(&format!("{variant}=>{id},")),
            "Incompatible Sequoia checkout: assigned algorithm IDs 37-44 are required. \
             Use scripts/run.sh /path/to/compatible/sequoia COMMAND ...; \
             see tools/pqc-vector-generator/README.md for the recorded revision."
        );
    }
}
