// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local-first encrypted vault storage and the item model.
//!
//! On disk a vault is a single JSON envelope holding the KDF parameters, the
//! salt, a random nonce and the base64 ciphertext. Everything user-owned - item
//! titles, usernames, passwords, notes - lives inside the ciphertext, so the
//! file leaks only the KDF cost and the ciphertext length.

mod item;
pub mod totp;
mod vault;

pub use item::{Item, ItemKind};
pub use krypton_crypto::{CryptoError, KdfParams, SALT_LEN};
pub use vault::{FORMAT, VERSION, Vault, VaultError};
