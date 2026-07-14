//! Persistent tower identity.
//!
//! The tower's public key is how clients recognise and verify its attestations,
//! so it must be stable across restarts. The secret key is stored once in the
//! data directory (0600) and reloaded thereafter; a fresh key is generated only
//! on first run. This is a small file, kept out of the sled store so it is easy
//! to back up and rotate deliberately.

use secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey};
use std::path::{Path, PathBuf};

fn key_path(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("tower_identity.key")
}

/// Load the tower's identity key, or generate and persist one on first run.
pub fn load_or_create(data_dir: &str) -> anyhow::Result<SecretKey> {
    let path = key_path(data_dir);
    if let Ok(text) = std::fs::read_to_string(&path) {
        let bytes = hex::decode(text.trim())?;
        return Ok(SecretKey::from_slice(&bytes)?);
    }

    // First run: generate, then persist with restrictive permissions.
    let secp = Secp256k1::new();
    let (sk, _pk) = secp.generate_keypair(&mut OsRng);
    std::fs::create_dir_all(data_dir).ok();
    std::fs::write(&path, hex::encode(sk.secret_bytes()))?;
    restrict_permissions(&path);
    Ok(sk)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = std::fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = std::fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_stable_across_loads() {
        let dir = std::env::temp_dir().join(format!("sentinel-id-test-{}", std::process::id()));
        let d = dir.to_str().unwrap();
        let k1 = load_or_create(d).unwrap();
        let k2 = load_or_create(d).unwrap();
        assert_eq!(k1.secret_bytes(), k2.secret_bytes(), "identity must persist");
        std::fs::remove_dir_all(&dir).ok();
    }
}
