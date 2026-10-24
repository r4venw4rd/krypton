# krypton

A local-first, zero-knowledge, device-bound trust fabric and identity/secret
orchestration platform.

Status: **Phase 1 (core crypto + local-first storage) and the CLI baseline are
in place.** Item orchestration, device pairing, the TUI and sharing come next -
see [plan.md](plan.md).

## Layout

| Crate | Purpose |
| --- | --- |
| `crates/crypto` | Argon2id key derivation, XChaCha20-Poly1305 AEAD, secret key type |
| `crates/core` | Vault file format, item model, encrypted storage, import/export, TOTP, audit, device identities |
| `crates/cli` | `krypton` binary (clap): `init`, `unlock`, `lock`, `export`, `import` |
| `crates/tui` | Placeholder for the Phase 4 Ratatui interface |

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

## Usage

The vault defaults to `~/.krypton/vault.kv`; override it with `--vault PATH`,
`KRYPTON_HOME`, or `KRYPTON_VAULT`.

```sh
# Create a new vault (prompts for the master password twice)
krypton init

# Decrypt and list items (secrets stay hidden)
krypton unlock

# Re-encrypt with a fresh nonce
krypton lock

# Rotate the master password (fresh salt, fresh nonce)
krypton change-password

# Generate a TOTP code for an item (title substring or id prefix)
krypton totp github

# Check credentials for weak, common and reused passwords
krypton audit

# Create this device's Ed25519 identity and list the trust list
krypton device init --name laptop
krypton device list

# Import / export plaintext JSON bodies: {"items": [...]}
krypton import --in backup.json
krypton export --out backup.json      # prints a plaintext warning

# Pick a specific vault
krypton --vault ./work.kv unlock
```

Passwords are read from a hidden terminal prompt; when stdin is piped the first
line is used (two lines for `init`/`import`), which is how the CLI is scripted
and tested.

## Crypto design

* **Key derivation:** Argon2id, 64 MiB / 3 passes / 1 lane by default. The
  parameters and a 16-byte salt are stored in the vault header, so cost can be
  raised later without breaking old vaults.
* **Encryption:** XChaCha20-Poly1305 with a random 24-byte nonce per save.
* **Header binding:** format, version, KDF parameters and salt are passed as
  AEAD associated data, so editing the header (e.g. lowering the KDF cost) makes
  decryption fail instead of silently weakening the vault.
* **No plaintext on disk:** only the header and ciphertext are written. Vault
  and export files are created with `0600` permissions and replaced atomically.
* **No key at rest:** the derived key lives only in memory in a `SecretKey`
  that zeroizes on drop; nothing is cached between commands. `Debug` output for
  keys and item secrets is redacted.

### Device identities (Phase 3, in progress)

Each device gets its own Ed25519 keypair. The seed lives in
`vault.device.key` next to the vault (mode `0600`), while only the public key
is stored inside the encrypted vault, so copying `vault.kv` to another machine
does not give it a trusted identity. `krypton device list` marks the entry
backed by the local key with `*` and shows short fingerprints.

The pairing handshake, signed trust edges and TPM/secure-enclave binding are
not implemented yet, and the local seed file is protected by file permissions
alone rather than by the OS keyring.

### Known limitations (Phase 1)

* A wrong password and a corrupted vault are reported identically by design;
  there is no separate authentication tag to distinguish them.
* There is no password rotation command yet, and no metadata (creation time,
  device identity) in the header.
* `export` writes decrypted secrets to disk by design; delete the file
  afterwards.

## License

Copyright (C) 2026 r4venw4rd

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>.

The full license text is available in [LICENSE](LICENSE).
