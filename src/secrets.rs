//! Credentials at rest, encrypted with AES-256-GCM.
//!
//! # Design decision: a fresh random nonce for every encryption, never a counter
//!
//! GCM fails catastrophically on nonce reuse — two messages under the same
//! key and nonce leak their XOR and, worse, allow forgery by recovering the
//! authentication subkey. A counter would be fine if this store were the only
//! writer and never restored from a backup, and neither assumption survives
//! contact with a real machine. A 96-bit random nonce per encryption is the
//! option that stays correct when the file is copied, restored or edited by
//! two processes at once.
//!
//! # Design decision: the secret's name is authenticated as associated data
//!
//! Without this, an attacker with write access to the store can swap two
//! ciphertexts and a tool configured for `staging_token` silently receives
//! `production_token`. Both decrypt perfectly; both tags verify. Binding the
//! name in as AAD makes that swap fail closed, and it costs nothing.
//!
//! # Design decision: the key never lives in this repository or in the store
//!
//! It comes from the environment. A store file is therefore useless on its own,
//! which is what makes it safe to keep beside the code it configures.
//!
//! # Design decision: cryptographic errors say nothing
//!
//! `GritError::Crypto` carries no detail. Telling a caller whether the key was
//! wrong, the tag failed or the nonce was malformed is how oracles get built.

use std::collections::BTreeMap;
use std::path::Path;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::error::{GritError, Result};

const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
pub const KEY_ENV: &str = "GRIT_MASTER_KEY";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretStore {
    /// name -> hex(nonce) : hex(ciphertext||tag)
    #[serde(default)]
    entries: BTreeMap<String, StoredSecret>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSecret {
    nonce: String,
    ciphertext: String,
}

/// A decrypted secret that scrubs itself when dropped.
///
/// Rust will not stop a copy being made if a caller asks for one, so this is a
/// meaningful reduction in exposure rather than a guarantee. It ensures the
/// obvious path — read it, use it, drop it — does not leave plaintext sitting
/// in freed memory for the rest of the process's life.
pub struct Secret(String);

impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the value, not even in a debug log. A secret that
        // appears in a stack trace is a secret that appears in a bug report.
        f.write_str("Secret(<redacted>)")
    }
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn from_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(GritError::Crypto);
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| GritError::Crypto))
        .collect()
}

/// Read the master key from the environment.
fn key_from_env() -> Result<[u8; KEY_BYTES]> {
    let raw = std::env::var(KEY_ENV).map_err(|_| {
        GritError::Config(format!(
            "{KEY_ENV} is not set. It must be {} hex characters ({KEY_BYTES} bytes). \
             Generate one with: openssl rand -hex {KEY_BYTES}",
            KEY_BYTES * 2
        ))
    })?;
    let mut bytes = from_hex(raw.trim())
        .map_err(|_| GritError::Config(format!("{KEY_ENV} must be valid hex")))?;
    if bytes.len() != KEY_BYTES {
        bytes.zeroize();
        return Err(GritError::Config(format!(
            "{KEY_ENV} must decode to exactly {KEY_BYTES} bytes"
        )));
    }
    let mut key = [0u8; KEY_BYTES];
    key.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(key)
}

impl SecretStore {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw)
                .map_err(|e| GritError::Config(format!("invalid secret store: {e}"))),
            // A missing store is an empty store, not an error. Nothing has been
            // saved yet, which is a perfectly ordinary state on first run.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(GritError::io(path, e)),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let raw = serde_json::to_string_pretty(self)
            .map_err(|e| GritError::Config(format!("cannot serialise store: {e}")))?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| GritError::io(parent, e))?;
        }
        std::fs::write(path, raw).map_err(|e| GritError::io(path, e))
    }

    pub fn names(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }

    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }

    /// Encrypt and store a secret under `name`, replacing any existing entry.
    pub fn put(&mut self, name: &str, plaintext: &str) -> Result<()> {
        let mut key = key_from_env()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    // Binds the ciphertext to its name, so entries cannot be
                    // swapped by anyone who can write this file.
                    aad: name.as_bytes(),
                },
            )
            .map_err(|_| GritError::Crypto)?;
        key.zeroize();

        self.entries.insert(
            name.to_string(),
            StoredSecret {
                nonce: to_hex(nonce.as_slice()),
                ciphertext: to_hex(&ciphertext),
            },
        );
        Ok(())
    }

    /// Decrypt the secret stored under `name`.
    pub fn get(&self, name: &str) -> Result<Secret> {
        let entry = self.entries.get(name).ok_or_else(|| GritError::Denied {
            reason: format!("no secret named {name}"),
        })?;

        let nonce_bytes = from_hex(&entry.nonce)?;
        if nonce_bytes.len() != NONCE_BYTES {
            return Err(GritError::Crypto);
        }
        let ciphertext = from_hex(&entry.ciphertext)?;

        let mut key = key_from_env()?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
        let plaintext = cipher
            .decrypt(
                Nonce::from_slice(&nonce_bytes),
                Payload {
                    msg: &ciphertext,
                    aad: name.as_bytes(),
                },
            )
            .map_err(|_| GritError::Crypto)?;
        key.zeroize();

        let mut owned = plaintext;
        let text = String::from_utf8(owned.clone()).map_err(|_| GritError::Crypto)?;
        owned.zeroize();
        Ok(Secret(text))
    }

    pub fn remove(&mut self, name: &str) -> bool {
        self.entries.remove(name).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tests set the key directly rather than through the process environment
    /// where possible; where the env is needed it is set and removed around the
    /// assertion. `cargo test` runs these on threads, so each test sets the
    /// same value rather than different ones, which keeps them independent.
    const TEST_KEY: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

    fn with_key<T>(f: impl FnOnce() -> T) -> T {
        std::env::set_var(KEY_ENV, TEST_KEY);
        f()
    }

    #[test]
    fn a_secret_round_trips() {
        with_key(|| {
            let mut store = SecretStore::default();
            store.put("api_token", "sk-live-abc123").expect("put");
            let got = store.get("api_token").expect("get");
            assert_eq!(got.expose(), "sk-live-abc123");
        });
    }

    #[test]
    fn the_stored_form_does_not_contain_the_plaintext() {
        with_key(|| {
            let mut store = SecretStore::default();
            store.put("api_token", "sk-live-abc123").expect("put");
            let json = serde_json::to_string(&store).expect("serialise");
            assert!(!json.contains("sk-live-abc123"), "plaintext leaked: {json}");
        });
    }

    #[test]
    fn two_encryptions_of_the_same_value_differ() {
        // If they matched, the nonce would be being reused, which is the one
        // mistake GCM does not survive.
        with_key(|| {
            let mut a = SecretStore::default();
            let mut b = SecretStore::default();
            a.put("t", "same value").expect("put");
            b.put("t", "same value").expect("put");
            let ja = serde_json::to_string(&a).expect("ser");
            let jb = serde_json::to_string(&b).expect("ser");
            assert_ne!(ja, jb, "identical ciphertexts mean a repeated nonce");
        });
    }

    #[test]
    fn swapping_two_entries_fails_closed() {
        // The attack the AAD binding exists to stop: an attacker with write
        // access to the store points `staging` at the production ciphertext.
        with_key(|| {
            let mut store = SecretStore::default();
            store.put("production_token", "PROD-SECRET").expect("put");
            store.put("staging_token", "STAGING-SECRET").expect("put");

            let prod = store
                .entries
                .get("production_token")
                .cloned()
                .expect("present");
            store.entries.insert("staging_token".into(), prod);

            let err = store.get("staging_token").expect_err("must not decrypt");
            assert_eq!(err.code(), "crypto_error");
        });
    }

    #[test]
    fn a_tampered_ciphertext_fails_closed() {
        with_key(|| {
            let mut store = SecretStore::default();
            store.put("t", "value").expect("put");
            if let Some(entry) = store.entries.get_mut("t") {
                // Flip one hex character. GCM's tag must catch this.
                let mut chars: Vec<char> = entry.ciphertext.chars().collect();
                chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
                entry.ciphertext = chars.into_iter().collect();
            }
            assert_eq!(
                store.get("t").expect_err("must fail").code(),
                "crypto_error"
            );
        });
    }

    #[test]
    fn a_wrong_key_fails_closed_and_says_nothing_useful() {
        std::env::set_var(KEY_ENV, TEST_KEY);
        let mut store = SecretStore::default();
        store.put("t", "value").expect("put");

        std::env::set_var(
            KEY_ENV,
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        );
        let err = store.get("t").expect_err("must fail");
        assert_eq!(err.code(), "crypto_error");
        assert_eq!(
            err.to_string(),
            "cryptographic operation failed",
            "the message must not distinguish a bad key from a bad tag"
        );
        std::env::set_var(KEY_ENV, TEST_KEY);
    }

    #[test]
    fn a_missing_secret_is_a_denial_not_a_crypto_error() {
        with_key(|| {
            let store = SecretStore::default();
            assert_eq!(store.get("absent").expect_err("must fail").code(), "denied");
        });
    }

    #[test]
    fn a_secret_never_prints_itself() {
        with_key(|| {
            let mut store = SecretStore::default();
            store.put("t", "TOP-SECRET-VALUE").expect("put");
            let s = store.get("t").expect("get");
            assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        });
    }

    #[test]
    fn a_missing_store_file_is_an_empty_store() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = SecretStore::load(&dir.path().join("nope.json")).expect("load");
        assert!(store.names().is_empty());
    }

    #[test]
    fn a_store_survives_a_save_and_load() {
        with_key(|| {
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("secrets.json");
            let mut store = SecretStore::default();
            store.put("t", "persisted").expect("put");
            store.save(&path).expect("save");

            let reloaded = SecretStore::load(&path).expect("load");
            assert_eq!(reloaded.get("t").expect("get").expose(), "persisted");
        });
    }

    #[test]
    fn a_short_key_is_rejected_at_load() {
        std::env::set_var(KEY_ENV, "00010203");
        let mut store = SecretStore::default();
        let err = store.put("t", "v").expect_err("must reject");
        assert_eq!(err.code(), "config_error");
        std::env::set_var(KEY_ENV, TEST_KEY);
    }
}
