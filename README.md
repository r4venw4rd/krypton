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
| `crates/cli` | `krypton` binary (clap): `init`, `add`, `unlock`, `lock`, `export`, `import`, `device`, `sync`, `audit`, `totp` |
| `crates/tui` | Placeholder for the Phase 4 Ratatui interface |

## Build and test

```sh
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features
```

## Quality gates

The lint policy lives in the workspace manifest, not in a command someone has
to remember - so `cargo clippy` fails on the same rules everywhere:

* `rust`: `unsafe_code = "forbid"`, `missing_docs = "deny"`.
* `clippy`: `all`, `pedantic`, `nursery` and `cargo` are denied.
* The only allow is `clippy::multiple_crate_versions`: `serde_derive` pulls
  `syn` 2 while thiserror's macro pulls `syn` 3, and neither copy is ours to
  drop.

Verified by intentionally adding an undocumented public item: clippy exits
non-zero with `missing documentation for a function`, and the tree is green
again once that probe is removed.

## Usage

The vault defaults to `~/.krypton/vault.kv`; override it with `--vault PATH`,
`KRYPTON_HOME`, or `KRYPTON_VAULT`.

```sh
# Create a new vault (prompts for the master password twice)
krypton init

# Generate a strong password (24 chars, one of each class, OS CSPRNG)
krypton generate
krypton generate --length 32 --no-symbols

# Add items (the stored password is prompted for; --password for scripts)
krypton add credential --title github --username r4venw4rd --url https://github.com
krypton add note --title recovery --body "codes are in the safe"
krypton add totp --title github-2fa --secret GEZDGNBVGY3TQOJQ --issuer GitHub

# Decrypt and list items (secrets stay hidden)
krypton unlock

# Reveal one item, or delete it after confirmation
krypton show github
krypton remove github --force

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

# Pair with another device (see "Device identities" below)
krypton device invite

# Exchange an encrypted update with a paired device
krypton sync export --to phone --out payload.bin
krypton sync import --in payload.bin

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

Device A invites, device B answers, device A confirms (pass the base64 lines
between the machines over any channel):

```sh
# device A
krypton device invite

# device B, with A's invite blob
krypton device accept --invite <blob>

# device A, with B's acceptance blob
krypton device complete --invite <blob> --response <blob>
```

The invite and acceptance are signed over a shared nonce, so both sides end up
holding the other's verified public key. Compare the printed fingerprints out
of band; invites expire after 24 hours and pairing blobs are signed but not
encrypted (device names and public keys are visible to whoever carries them).

Signed trust edges beyond "this key is in my list", revocation and
TPM/secure-enclave binding are not implemented yet; the local seed file is
protected by file permissions alone rather than by the OS keyring.

### Device sync (Phase 3, in progress)

Paired devices exchange an encrypted copy of the vault body as a file (any
transport works - the payload is opaque bytes):

```sh
# sending device
krypton sync export --to phone --out payload.bin

# receiving device (already paired, same vault key material)
krypton sync import --in payload.bin
```

The payload is sealed with `HKDF-SHA256(vault key, sender_pub || recipient_pub)`
and signed by the sender's device key, so the recipient rejects payloads from
unpaired devices or addressed to another machine. Merging is last-write-wins
per item id plus a union of device records; deletions are not propagated, there
is no CRDT or network transport yet, and both devices must have unlocked a vault
built from the same salt and master password (for now: the same vault file).

### Known limitations (Phase 1)

* A wrong password and a corrupted vault are reported identically by design;
  there is no separate authentication tag to distinguish them.
* The vault header carries no metadata beyond the format version, KDF
  parameters and salt (no creation time, no owner identity).
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
