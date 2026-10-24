// SPDX-License-Identifier: AGPL-3.0-or-later
//! Vault items: credentials, TOTP seeds and secure notes.

use std::fmt;

use krypton_crypto::{CryptoError, random_bytes};
use serde::{Deserialize, Serialize};

/// One entry in the vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    /// Random 128-bit identifier, hex encoded.
    pub id: String,
    /// Human-readable label shown by the CLI/TUI.
    pub title: String,
    /// Secret payload; flattened so the JSON stays readable.
    #[serde(flatten)]
    pub kind: ItemKind,
}

impl Item {
    /// Builds an item with a freshly generated identifier.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::Random`] if the OS CSPRNG is unavailable.
    pub fn new(title: impl Into<String>, kind: ItemKind) -> Result<Self, CryptoError> {
        let id = random_bytes::<16>()?;
        Ok(Self {
            id: hex(&id),
            title: title.into(),
            kind,
        })
    }

    /// Short type label for listings.
    #[must_use]
    pub const fn kind_label(&self) -> &'static str {
        self.kind.label()
    }
}

/// The secret material an item carries.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItemKind {
    /// Username/password pair for a site or service.
    Credential {
        /// Login name for the account.
        username: String,
        /// Password or other secret value.
        #[serde(default)]
        password: String,
        /// Site or service the credential belongs to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
        /// Free-form notes (recovery hints, security questions, ...).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        notes: Option<String>,
    },
    /// Time-based one-time password seed.
    Totp {
        /// Base32 shared secret.
        secret: String,
        /// Service that issued the seed, e.g. `GitHub`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        issuer: Option<String>,
        /// Account name the seed belongs to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
    },
    /// Encrypted free-form text.
    Note {
        /// Note contents.
        body: String,
    },
}

/// Redacts secrets so `{:?}` on an item never lands credentials in a log.
impl fmt::Debug for ItemKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Credential { username, url, .. } => f
                .debug_struct("Credential")
                .field("username", username)
                .field("password", &"<redacted>")
                .field("url", url)
                .finish(),
            Self::Totp {
                issuer, account, ..
            } => f
                .debug_struct("Totp")
                .field("secret", &"<redacted>")
                .field("issuer", issuer)
                .field("account", account)
                .finish(),
            Self::Note { .. } => f.debug_struct("Note").field("body", &"<redacted>").finish(),
        }
    }
}

impl ItemKind {
    /// Machine-readable type label, matching the JSON `type` field.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Credential { .. } => "credential",
            Self::Totp { .. } => "totp",
            Self::Note { .. } => "note",
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_item_gets_unique_hex_id() {
        let a = Item::new("a", ItemKind::Note { body: "x".into() }).unwrap();
        let b = Item::new("b", ItemKind::Note { body: "y".into() }).unwrap();
        assert_eq!(a.id.len(), 32);
        assert!(a.id.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a.id, b.id);
    }

    #[test]
    fn item_round_trips_through_json() {
        let item = Item::new(
            "github",
            ItemKind::Credential {
                username: "r4venw4rd".into(),
                password: "hunter2".into(),
                url: Some("https://github.com".into()),
                notes: None,
            },
        )
        .unwrap();

        let json = serde_json::to_string(&item).unwrap();
        assert!(json.contains("\"type\":\"credential\""));
        let parsed: Item = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, item.id);
        assert_eq!(parsed.kind_label(), "credential");
    }
}
