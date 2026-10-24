// SPDX-License-Identifier: AGPL-3.0-or-later
//! Time-limited share tokens for a single item.
//!
//! A token is a bearer credential: the secret half travels inside the token, so
//! whoever holds the string can read the shared item until it expires. The item
//! payload is still sealed with an HKDF-derived key, which keeps the payload
//! opaque to anything that only sees the header (a log line, a file name) and
//! gives a place to bind the scope and expiry as associated data.
//!
//! Nothing is sent anywhere: tokens are produced and redeemed offline, the
//! recipient needs no vault, and the vault keeps an audit [`ShareRecord`] for
//! every token it issued.

use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hkdf::Hkdf;
use krypton_crypto::aead::{self, NONCE_LEN};
use krypton_crypto::{CryptoError, KEY_LEN, SecretKey, random_bytes};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

use crate::{Item, ItemKind, Vault};

/// Marker for a share token.
pub const TOKEN_TYPE: &str = "krypton-share";
/// Token format version understood by this build.
pub const VERSION: u32 = 1;

const HKDF_SALT: &[u8] = b"krypton-share-v1";
const TOKEN_KEY_LEN: usize = 32;

/// What a token exposes about the shared item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    /// Full item, secrets included.
    Read,
    /// Title, type and account hints; secrets stay blank.
    Metadata,
}

impl Scope {
    /// Lower-case label used by the CLI.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Metadata => "metadata",
        }
    }
}

impl FromStr for Scope {
    type Err = ShareError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "read" => Ok(Self::Read),
            "metadata" => Ok(Self::Metadata),
            other => Err(ShareError::UnknownScope(other.to_string())),
        }
    }
}

/// Audit entry stored in the vault for every issued token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareRecord {
    /// Random identifier printed with the token.
    pub token_id: String,
    /// Item the token unlocks.
    pub item_id: String,
    /// Title at issue time, so the record stays readable after a rename.
    pub item_title: String,
    /// Scope the token was issued with.
    pub scope: Scope,
    /// Unix timestamp (seconds) of issue.
    pub created_at: u64,
    /// Unix timestamp (seconds) after which the token is refused.
    pub expires_at: u64,
}

impl ShareRecord {
    /// Remaining lifetime in seconds at `now`, or zero once expired.
    #[must_use]
    pub const fn remaining(&self, now: u64) -> u64 {
        self.expires_at.saturating_sub(now)
    }

    /// Whether the token has expired at `now`.
    #[must_use]
    pub const fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// A freshly minted token plus the audit record for it.
#[derive(Debug, Clone)]
pub struct CreatedShare {
    /// Bearer token string to hand to the recipient.
    pub token: String,
    /// Record to append to the vault's audit log.
    pub record: ShareRecord,
}

/// A redeemed token's contents.
#[derive(Debug, Clone)]
pub struct RedeemedShare {
    /// Item, already redacted when the scope is [`Scope::Metadata`].
    pub item: Item,
    /// Scope the token was issued with.
    pub scope: Scope,
    /// Unix timestamp (seconds) the token expires at.
    pub expires_at: u64,
    /// Identifier printed next to the audit record.
    pub token_id: String,
}

/// Failures from creating or redeeming share tokens.
#[derive(Debug, Error)]
pub enum ShareError {
    /// The token is not valid base64.
    #[error("share token is not valid base64")]
    Encoding,
    /// The token header is not valid JSON.
    #[error("share token is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The token is not a krypton share token.
    #[error("unexpected share token type: {0}")]
    UnexpectedType(String),
    /// The token uses a newer format.
    #[error("unsupported share token version {0}")]
    UnsupportedVersion(u32),
    /// The token names a scope this build does not implement.
    #[error("unknown share scope: {0}")]
    UnknownScope(String),
    /// The requested item is not in the vault.
    #[error("no item with id {0} in the vault")]
    ItemNotFound(String),
    /// A zero or overflowing lifetime was requested.
    #[error("share lifetime must be between 1 second and 100 years")]
    InvalidTtl,
    /// The token is past its expiry.
    #[error("share token expired at {0} (unix time)")]
    Expired(u64),
    /// A baked-in TTL string could not be parsed.
    #[error("invalid lifetime {0:?}; use 30m, 24h, 7d or a number of seconds")]
    InvalidTtlFormat(String),
    /// The token key or nonce has the wrong length.
    #[error("share token is malformed: {0}")]
    Malformed(String),
    /// The sealed payload did not open.
    #[error("share token could not be decrypted")]
    Decrypt,
    /// A crypto primitive failed.
    #[error(transparent)]
    Crypto(#[from] CryptoError),
}

/// Creates a token for `item_id` valid for `ttl_secs` seconds.
///
/// # Errors
///
/// Returns [`ShareError::ItemNotFound`] when the id is unknown,
/// [`ShareError::InvalidTtl`] for a zero or absurd lifetime, and crypto or JSON
/// errors while sealing the item.
pub fn create_share(
    vault: &Vault,
    item_id: &str,
    scope: Scope,
    ttl_secs: u64,
) -> Result<CreatedShare, ShareError> {
    create_share_at(vault, item_id, scope, ttl_secs, now())
}

/// Creates a token with an explicit issue time (tests).
///
/// # Errors
///
/// Same as [`create_share`].
pub fn create_share_at(
    vault: &Vault,
    item_id: &str,
    scope: Scope,
    ttl_secs: u64,
    created_at: u64,
) -> Result<CreatedShare, ShareError> {
    if ttl_secs == 0 || created_at.checked_add(ttl_secs).is_none() {
        return Err(ShareError::InvalidTtl);
    }

    let item = vault
        .items()
        .iter()
        .find(|item| item.id == item_id)
        .ok_or_else(|| ShareError::ItemNotFound(item_id.to_string()))?;

    let expires_at = created_at + ttl_secs;
    let token_key = SecretKey::from_bytes(random_bytes::<TOKEN_KEY_LEN>()?);
    let token_id = hex(&random_bytes::<8>()?);
    let key = derive_key(&token_key, &token_id)?;
    let aad = associated_data(scope, created_at, expires_at, &token_id);

    let payload = serde_json::to_vec(item)?;
    let sealed = aead::seal(&key, &payload, aad.as_bytes())?;

    let wire = TokenWire {
        kind: TOKEN_TYPE.to_string(),
        version: VERSION,
        scope,
        created_at,
        expires_at,
        token_id: token_id.clone(),
        nonce: BASE64.encode(sealed.nonce),
        ciphertext: BASE64.encode(sealed.ciphertext),
        key: BASE64.encode(token_key.as_bytes()),
    };

    Ok(CreatedShare {
        token: BASE64.encode(serde_json::to_vec(&wire)?),
        record: ShareRecord {
            token_id,
            item_id: item.id.clone(),
            item_title: item.title.clone(),
            scope,
            created_at,
            expires_at,
        },
    })
}

/// Verifies and opens a token.
///
/// # Errors
///
/// Returns [`ShareError::Expired`] once the TTL has passed,
/// [`ShareError::Decrypt`] for a modified ciphertext, and the structural errors
/// documented on [`ShareError`] for malformed input.
pub fn redeem(token: &str) -> Result<RedeemedShare, ShareError> {
    redeem_at(token, now())
}

/// Redeems a token against an explicit "now" (tests).
///
/// # Errors
///
/// Same as [`redeem`], evaluated at `now`.
pub fn redeem_at(token: &str, now: u64) -> Result<RedeemedShare, ShareError> {
    let raw = BASE64
        .decode(token.trim())
        .map_err(|_| ShareError::Encoding)?;
    let wire: TokenWire = serde_json::from_slice(&raw)?;

    if wire.kind != TOKEN_TYPE {
        return Err(ShareError::UnexpectedType(wire.kind));
    }
    if wire.version != VERSION {
        return Err(ShareError::UnsupportedVersion(wire.version));
    }
    if now >= wire.expires_at {
        return Err(ShareError::Expired(wire.expires_at));
    }

    let token_key_bytes = decode_fixed::<TOKEN_KEY_LEN>(&wire.key)?;
    let token_key = SecretKey::from_bytes(token_key_bytes);
    let key = derive_key(&token_key, &wire.token_id)?;

    let nonce = decode_fixed::<NONCE_LEN>(&wire.nonce)?;
    let ciphertext = BASE64
        .decode(&wire.ciphertext)
        .map_err(|_| ShareError::Encoding)?;
    let aad = associated_data(wire.scope, wire.created_at, wire.expires_at, &wire.token_id);

    let plaintext =
        aead::open(&key, &nonce, &ciphertext, aad.as_bytes()).map_err(|_| ShareError::Decrypt)?;
    let item: Item = serde_json::from_slice(&plaintext)?;

    Ok(RedeemedShare {
        item: match wire.scope {
            Scope::Read => item,
            Scope::Metadata => redacted(&item),
        },
        scope: wire.scope,
        expires_at: wire.expires_at,
        token_id: wire.token_id,
    })
}

/// Parses lifetimes like `30m`, `24h`, `7d` or a bare number of seconds.
///
/// # Errors
///
/// Returns [`ShareError::InvalidTtlFormat`] for an unparsable value, and
/// [`ShareError::InvalidTtl`] for zero or absurd lifetimes.
pub fn parse_ttl(text: &str) -> Result<u64, ShareError> {
    let text = text.trim();
    let (value, multiplier) = match text.chars().last() {
        Some('s') => (&text[..text.len() - 1], 1),
        Some('m') => (&text[..text.len() - 1], 60),
        Some('h') => (&text[..text.len() - 1], 3_600),
        Some('d') => (&text[..text.len() - 1], 86_400),
        _ => (text, 1),
    };

    let value: u64 = value
        .parse()
        .map_err(|_| ShareError::InvalidTtlFormat(text.to_string()))?;
    let seconds = value
        .checked_mul(multiplier)
        .ok_or(ShareError::InvalidTtl)?;

    if seconds == 0 || seconds > 100 * 365 * 86_400 {
        return Err(ShareError::InvalidTtl);
    }
    Ok(seconds)
}

fn redacted(item: &Item) -> Item {
    let mut copy = item.clone();
    match &mut copy.kind {
        ItemKind::Credential {
            password, notes, ..
        } => {
            password.clear();
            *notes = None;
        }
        ItemKind::Totp { secret, .. } => secret.clear(),
        ItemKind::Note { body } => body.clear(),
    }
    copy
}

fn derive_key(token_key: &SecretKey, token_id: &str) -> Result<SecretKey, ShareError> {
    let hkdf = Hkdf::<Sha256>::new(Some(HKDF_SALT), token_key.as_bytes());
    let mut okm = [0u8; KEY_LEN];
    hkdf.expand(token_id.as_bytes(), &mut okm)
        .map_err(|_| ShareError::Malformed("HKDF rejected the token key length".to_string()))?;
    Ok(SecretKey::from_bytes(okm))
}

fn associated_data(scope: Scope, created_at: u64, expires_at: u64, token_id: &str) -> String {
    format!(
        "{TOKEN_TYPE}\n{VERSION}\n{}\n{created_at}\n{expires_at}\n{token_id}",
        scope.label()
    )
}

fn decode_fixed<const N: usize>(encoded: &str) -> Result<[u8; N], ShareError> {
    let bytes = BASE64.decode(encoded).map_err(|_| ShareError::Encoding)?;
    bytes
        .try_into()
        .map_err(|_| ShareError::Malformed(format!("expected {N} bytes")))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[derive(Serialize, Deserialize)]
struct TokenWire {
    #[serde(rename = "type")]
    kind: String,
    version: u32,
    scope: Scope,
    created_at: u64,
    expires_at: u64,
    token_id: String,
    nonce: String,
    ciphertext: String,
    key: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Item, ItemKind, KdfParams, Vault};

    const NOW: u64 = 1_800_000_000;

    struct Fixture {
        dir: std::path::PathBuf,
        vault: Vault,
        item_id: String,
    }

    impl Fixture {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};

            static NEXT: AtomicUsize = AtomicUsize::new(0);

            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "krypton-share-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("vault.kv");
            let mut vault =
                Vault::create_with_params(&path, "pw", KdfParams::weak_for_tests()).unwrap();

            let item = Item::new(
                "github",
                ItemKind::Credential {
                    username: "r4venw4rd".into(),
                    password: "s3cret-value".into(),
                    url: Some("https://github.com".into()),
                    notes: Some("private note".into()),
                },
            )
            .unwrap();
            let id = item.id.clone();
            vault.items_mut().push(item);
            vault.save().unwrap();

            Self {
                dir,
                vault,
                item_id: id,
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn read_scope_round_trips_the_whole_item() {
        let fixture = Fixture::new();
        let share =
            create_share_at(&fixture.vault, &fixture.item_id, Scope::Read, 3_600, NOW).unwrap();

        let redeemed = redeem_at(&share.token, NOW + 60).unwrap();
        assert_eq!(redeemed.scope, Scope::Read);
        assert_eq!(redeemed.expires_at, NOW + 3_600);
        assert_eq!(redeemed.item.title, "github");
        match &redeemed.item.kind {
            ItemKind::Credential { password, .. } => assert_eq!(password, "s3cret-value"),
            other => panic!("unexpected kind: {other:?}"),
        }
    }

    #[test]
    fn metadata_scope_blanks_the_secrets() {
        let fixture = Fixture::new();
        let share =
            create_share_at(&fixture.vault, &fixture.item_id, Scope::Metadata, 60, NOW).unwrap();

        let redeemed = redeem_at(&share.token, NOW).unwrap();
        match &redeemed.item.kind {
            ItemKind::Credential {
                username,
                password,
                notes,
                ..
            } => {
                assert_eq!(username, "r4venw4rd");
                assert!(password.is_empty());
                assert!(notes.is_none());
            }
            other => panic!("unexpected kind: {other:?}"),
        }
    }

    #[test]
    fn token_expires_exactly_at_the_deadline() {
        let fixture = Fixture::new();
        let share =
            create_share_at(&fixture.vault, &fixture.item_id, Scope::Read, 60, NOW).unwrap();

        assert!(redeem_at(&share.token, NOW + 59).is_ok());
        let err = redeem_at(&share.token, NOW + 60).unwrap_err();
        assert!(matches!(err, ShareError::Expired(at) if at == NOW + 60));
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let fixture = Fixture::new();
        let share =
            create_share_at(&fixture.vault, &fixture.item_id, Scope::Read, 60, NOW).unwrap();

        let mut wire: serde_json::Value =
            serde_json::from_slice(&BASE64.decode(&share.token).unwrap()).unwrap();
        let mut bytes = wire["ciphertext"].as_str().unwrap().as_bytes().to_vec();
        let last = bytes.len() - 2;
        bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
        wire["ciphertext"] = serde_json::Value::from(String::from_utf8(bytes).unwrap());
        let tampered = BASE64.encode(serde_json::to_vec(&wire).unwrap());

        assert!(matches!(
            redeem_at(&tampered, NOW),
            Err(ShareError::Decrypt)
        ));
    }

    #[test]
    fn extending_the_expiry_breaks_the_tag() {
        let fixture = Fixture::new();
        let share =
            create_share_at(&fixture.vault, &fixture.item_id, Scope::Read, 60, NOW).unwrap();

        let mut wire: serde_json::Value =
            serde_json::from_slice(&BASE64.decode(&share.token).unwrap()).unwrap();
        wire["expires_at"] = serde_json::Value::from(NOW + 10_000);
        let forged = BASE64.encode(serde_json::to_vec(&wire).unwrap());

        assert!(matches!(redeem_at(&forged, NOW), Err(ShareError::Decrypt)));
    }

    #[test]
    fn audit_record_tracks_the_token() {
        let fixture = Fixture::new();
        let share =
            create_share_at(&fixture.vault, &fixture.item_id, Scope::Read, 3_600, NOW).unwrap();

        assert_eq!(share.record.item_id, fixture.item_id);
        assert_eq!(share.record.item_title, "github");
        assert_eq!(share.record.remaining(NOW + 600), 3_000);
        assert!(!share.record.is_expired(NOW + 3_599));
        assert!(share.record.is_expired(NOW + 3_600));
        assert_eq!(share.record.token_id.len(), 16);
    }

    #[test]
    fn unknown_item_and_bad_ttl_are_rejected() {
        let fixture = Fixture::new();
        assert!(matches!(
            create_share_at(&fixture.vault, "missing", Scope::Read, 60, NOW),
            Err(ShareError::ItemNotFound(_))
        ));
        assert!(matches!(
            create_share_at(&fixture.vault, &fixture.item_id, Scope::Read, 0, NOW),
            Err(ShareError::InvalidTtl)
        ));
        assert!(matches!(
            create_share_at(&fixture.vault, &fixture.item_id, Scope::Read, u64::MAX, 1),
            Err(ShareError::InvalidTtl)
        ));
    }

    #[test]
    fn ttl_parser_accepts_units_and_seconds() {
        assert_eq!(parse_ttl("30m").unwrap(), 1_800);
        assert_eq!(parse_ttl("24h").unwrap(), 86_400);
        assert_eq!(parse_ttl("7d").unwrap(), 604_800);
        assert_eq!(parse_ttl("45s").unwrap(), 45);
        assert_eq!(parse_ttl("90").unwrap(), 90);
        assert!(matches!(parse_ttl("0"), Err(ShareError::InvalidTtl)));
        assert!(matches!(
            parse_ttl("soon"),
            Err(ShareError::InvalidTtlFormat(_))
        ));
        assert!(matches!(
            parse_ttl(""),
            Err(ShareError::InvalidTtlFormat(_))
        ));
    }

    #[test]
    fn scopes_parse_from_labels() {
        assert_eq!("read".parse::<Scope>().unwrap(), Scope::Read);
        assert_eq!("METADATA".parse::<Scope>().unwrap(), Scope::Metadata);
        assert!(matches!(
            "write".parse::<Scope>(),
            Err(ShareError::UnknownScope(_))
        ));
    }

    #[test]
    fn wrong_magic_is_rejected() {
        let fixture = Fixture::new();
        let share =
            create_share_at(&fixture.vault, &fixture.item_id, Scope::Read, 60, NOW).unwrap();

        let mut wire: serde_json::Value =
            serde_json::from_slice(&BASE64.decode(&share.token).unwrap()).unwrap();
        wire["type"] = serde_json::Value::from("krypton-sync");
        let forged = BASE64.encode(serde_json::to_vec(&wire).unwrap());

        assert!(matches!(
            redeem_at(&forged, NOW),
            Err(ShareError::UnexpectedType(_))
        ));
    }
}
