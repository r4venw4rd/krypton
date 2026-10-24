// SPDX-License-Identifier: AGPL-3.0-or-later
//! The on-disk vault envelope and the encrypted round trip.
//!
//! File layout (JSON, v1):
//!
//! ```json
//! {
//!   "format": "krypton-vault",
//!   "version": 1,
//!   "kdf": { "algorithm": "argon2id", "memory_kib": 65536, ... },
//!   "salt": "<base64, 16 bytes>",
//!   "nonce": "<base64, 24 bytes>",
//!   "ciphertext": "<base64, body + tag>"
//! }
//! ```
//!
//! The header fields are bound to the ciphertext as AEAD associated data, so
//! lowering the KDF cost or swapping the salt makes decryption fail instead of
//! silently deriving a weaker key.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use krypton_crypto::aead::NONCE_LEN;
use krypton_crypto::{KdfParams, SALT_LEN, SecretKey, aead, derive_key, random_bytes};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Item;

/// Marker written into every vault file.
pub const FORMAT: &str = "krypton-vault";
/// Vault format version understood by this build.
pub const VERSION: u32 = 1;

/// Failures from creating, opening or writing a vault.
#[derive(Debug, Error)]
pub enum VaultError {
    /// A vault file already occupies the requested path.
    #[error("vault already exists at {0}")]
    AlreadyExists(PathBuf),
    /// The requested vault file does not exist.
    #[error("vault not found at {0}")]
    NotFound(PathBuf),
    /// An empty master password was supplied.
    #[error("master password must not be empty")]
    EmptyPassword,
    /// Wrong password or altered ciphertext; deliberately indistinguishable.
    #[error("incorrect password or corrupted vault")]
    Decrypt,
    /// The file is not a krypton vault.
    #[error("unsupported vault format: {0}")]
    UnsupportedFormat(String),
    /// The file was written by a newer format version.
    #[error("unsupported vault version {0}")]
    UnsupportedVersion(u32),
    /// A header field has a value the reader cannot use.
    #[error("vault file is malformed: {0}")]
    Malformed(String),
    /// Key derivation, sealing or opening failed.
    #[error(transparent)]
    Crypto(#[from] krypton_crypto::CryptoError),
    /// Reading or writing the vault file failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// The decrypted body or file envelope is not valid JSON.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

/// Everything that lives inside the encrypted envelope.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VaultBody {
    /// Secret entries: credentials, TOTP seeds and notes.
    #[serde(default)]
    pub items: Vec<Item>,
    /// Public identities of devices trusted by this vault. The matching private
    /// keys stay on each device (see [`crate::device`]).
    #[serde(default)]
    pub devices: Vec<crate::device::DeviceRecord>,
    /// Audit log of share tokens issued from this vault (see [`crate::share`]).
    #[serde(default)]
    pub shares: Vec<crate::share::ShareRecord>,
}

impl VaultBody {
    /// Builds a body from `items` with an empty trust list.
    #[must_use]
    pub const fn new(items: Vec<Item>) -> Self {
        Self {
            items,
            devices: Vec::new(),
            shares: Vec::new(),
        }
    }
}

/// A decrypted, unlocked vault bound to its file path.
pub struct Vault {
    path: PathBuf,
    kdf: KdfParams,
    salt: [u8; SALT_LEN],
    key: SecretKey,
    body: VaultBody,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("kdf", &self.kdf)
            .field("items", &self.body.items.len())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// Creates a new vault with default Argon2id parameters.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::EmptyPassword`] for an empty password,
    /// [`VaultError::AlreadyExists`] if the path is taken, and crypto or I/O
    /// errors while deriving the key and writing the file.
    pub fn create(path: impl Into<PathBuf>, password: &str) -> Result<Self, VaultError> {
        Self::create_with_params(path, password, KdfParams::default())
    }

    /// Creates a new vault with explicit KDF parameters (tests, migrations).
    ///
    /// # Errors
    ///
    /// Same as [`Vault::create`].
    pub fn create_with_params(
        path: impl Into<PathBuf>,
        password: &str,
        kdf: KdfParams,
    ) -> Result<Self, VaultError> {
        if password.is_empty() {
            return Err(VaultError::EmptyPassword);
        }
        let path = path.into();
        if path.exists() {
            return Err(VaultError::AlreadyExists(path));
        }

        let salt = random_bytes::<SALT_LEN>()?;
        let key = derive_key(password.as_bytes(), &salt, &kdf)?;
        let vault = Self {
            path,
            kdf,
            salt,
            key,
            body: VaultBody::default(),
        };
        vault.save()?;
        Ok(vault)
    }

    /// Opens and decrypts an existing vault.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::NotFound`] for a missing file,
    /// [`VaultError::Decrypt`] for a wrong password or tampered ciphertext,
    /// [`VaultError::UnsupportedFormat`] / [`VaultError::UnsupportedVersion`]
    /// for foreign files, [`VaultError::Malformed`] for broken base64, and
    /// crypto, JSON or I/O errors for everything else.
    pub fn open(path: impl AsRef<Path>, password: &str) -> Result<Self, VaultError> {
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            return Err(VaultError::NotFound(path));
        }

        let raw = fs::read(&path)?;
        let file: VaultFile = serde_json::from_slice(&raw)?;

        if file.format != FORMAT {
            return Err(VaultError::UnsupportedFormat(file.format));
        }
        if file.version != VERSION {
            return Err(VaultError::UnsupportedVersion(file.version));
        }

        let salt = decode_fixed::<SALT_LEN>(&file.salt, "salt")?;
        let nonce = decode_fixed::<NONCE_LEN>(&file.nonce, "nonce")?;
        let ciphertext = BASE64
            .decode(&file.ciphertext)
            .map_err(|_| VaultError::Malformed("ciphertext is not valid base64".into()))?;

        let key = derive_key(password.as_bytes(), &salt, &file.kdf)?;
        let aad = associated_data(&file.format, file.version, &file.kdf, &salt);
        let plaintext =
            aead::open(&key, &nonce, &ciphertext, &aad).map_err(|_| VaultError::Decrypt)?;

        let body: VaultBody = serde_json::from_slice(&plaintext)?;

        Ok(Self {
            path,
            kdf: file.kdf,
            salt,
            key,
            body,
        })
    }

    /// Path of the vault file on disk.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// KDF parameters recorded in the vault header.
    #[must_use]
    pub const fn kdf_params(&self) -> &KdfParams {
        &self.kdf
    }

    /// Items in the unlocked body.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        &self.body.items
    }

    /// Mutable access to the items; call [`Vault::save`] afterwards.
    pub const fn items_mut(&mut self) -> &mut Vec<Item> {
        &mut self.body.items
    }

    /// Device identities in the trust list.
    #[must_use]
    pub fn devices(&self) -> &[crate::device::DeviceRecord] {
        &self.body.devices
    }

    /// Mutable access to the trust list; call [`Vault::save`] afterwards.
    pub const fn devices_mut(&mut self) -> &mut Vec<crate::device::DeviceRecord> {
        &mut self.body.devices
    }

    /// Audit log of share tokens issued from this vault.
    #[must_use]
    pub fn shares(&self) -> &[crate::share::ShareRecord] {
        &self.body.shares
    }

    /// Mutable access to the share log; call [`Vault::save`] afterwards.
    pub const fn shares_mut(&mut self) -> &mut Vec<crate::share::ShareRecord> {
        &mut self.body.shares
    }

    /// The whole decrypted body.
    #[must_use]
    pub const fn body(&self) -> &VaultBody {
        &self.body
    }

    /// Mutable access to the body, for merges; call [`Vault::save`] afterwards.
    pub const fn body_mut(&mut self) -> &mut VaultBody {
        &mut self.body
    }

    /// The derived vault key, for in-crate consumers such as device sync.
    pub(crate) const fn secret_key(&self) -> &SecretKey {
        &self.key
    }

    /// Re-encrypts the body under a fresh nonce and writes it atomically.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Crypto`] if sealing fails, or I/O / JSON errors
    /// if the file cannot be serialised or written.
    pub fn save(&self) -> Result<(), VaultError> {
        self.write_encrypted(&self.salt, &self.key)
    }

    /// Re-derives the key from a new master password with a fresh salt.
    ///
    /// The file is written before the in-memory salt/key switch over, so a
    /// failed write leaves the vault openable with the old password.
    /// # Errors
    ///
    /// Returns [`VaultError::EmptyPassword`] for an empty password, and crypto
    /// or I/O errors if the new key cannot be derived or written.
    pub fn change_password(&mut self, new_password: &str) -> Result<(), VaultError> {
        if new_password.is_empty() {
            return Err(VaultError::EmptyPassword);
        }

        let salt = random_bytes::<SALT_LEN>()?;
        let key = derive_key(new_password.as_bytes(), &salt, &self.kdf)?;
        self.write_encrypted(&salt, &key)?;

        self.salt = salt;
        self.key = key;
        Ok(())
    }

    fn write_encrypted(&self, salt: &[u8; SALT_LEN], key: &SecretKey) -> Result<(), VaultError> {
        let plaintext = serde_json::to_vec(&self.body)?;
        let aad = associated_data(FORMAT, VERSION, &self.kdf, salt);
        let sealed = aead::seal(key, &plaintext, &aad)?;

        let file = VaultFile {
            format: FORMAT.to_string(),
            version: VERSION,
            kdf: self.kdf.clone(),
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(sealed.nonce),
            ciphertext: BASE64.encode(sealed.ciphertext),
        };

        write_private(&self.path, serde_json::to_vec_pretty(&file)?.as_slice())?;
        Ok(())
    }

    /// Writes the decrypted body to `path` as plaintext JSON. Lossy by design:
    /// the caller is responsible for warning the user.
    /// # Errors
    ///
    /// Returns [`VaultError::Json`] if the body cannot be serialised, or
    /// [`VaultError::Io`] if the file cannot be written.
    pub fn export_plaintext(&self, path: impl AsRef<Path>) -> Result<(), VaultError> {
        write_private(
            path.as_ref(),
            serde_json::to_vec_pretty(&self.body)?.as_slice(),
        )?;
        Ok(())
    }

    /// Reads a plaintext body (`{"items": [...]}`) and seals it into a new vault.
    ///
    /// # Errors
    ///
    /// Returns [`VaultError::Json`] for an unreadable source, plus any error
    /// from [`Vault::create`] or [`Vault::save`].
    pub fn import_plaintext(
        source: impl AsRef<Path>,
        destination: impl Into<PathBuf>,
        password: &str,
    ) -> Result<Self, VaultError> {
        let raw = fs::read(source)?;
        let body: VaultBody = serde_json::from_slice(&raw)?;
        let mut vault = Self::create(destination, password)?;
        vault.body = body;
        vault.save()?;
        Ok(vault)
    }
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    format: String,
    version: u32,
    kdf: KdfParams,
    salt: String,
    nonce: String,
    ciphertext: String,
}

/// Binds the header to the ciphertext so parameters cannot be edited.
fn associated_data(format: &str, version: u32, kdf: &KdfParams, salt: &[u8; SALT_LEN]) -> Vec<u8> {
    let header = format!(
        "{format}\n{version}\n{}:{}:{}:{}\n",
        kdf.algorithm, kdf.memory_kib, kdf.iterations, kdf.parallelism
    );
    let mut aad = header.into_bytes();
    aad.extend_from_slice(salt);
    aad
}

fn decode_fixed<const N: usize>(encoded: &str, field: &str) -> Result<[u8; N], VaultError> {
    let bytes = BASE64
        .decode(encoded)
        .map_err(|_| VaultError::Malformed(format!("{field} is not valid base64")))?;
    bytes
        .try_into()
        .map_err(|_| VaultError::Malformed(format!("{field} has the wrong length")))
}

/// Writes `bytes` with owner-only permissions, replacing `path` atomically.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let mut file = options.open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }

    if let Err(err) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    Ok(())
}
