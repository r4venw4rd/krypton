# Project Plan: Zero-Knowledge Device-Bound Trust Fabric

## 1. Project Overview & Architecture Vision
- **Core Concept:** A local-first, zero-knowledge, device-bound trust fabric and identity/secret orchestration platform (replacing traditional password managers).
- **Tech Stack:** Rust (memory safety, minimal runtime, robust crypto libraries like `ring` or `age`, CRDT/async sync), TUI/CLI (Ratatui / clap) + cross-platform GUI.
- **Key Differentiators:** 
  - Device Trust Graph (no central cloud plaintext/keys, peer-to-peer or encrypted blob sync via trusted devices).
  - Trustless Sharing (shareable access tokens with TTL and audit trails instead of raw credentials).
  - Threshold Social Recovery (e.g., 3-of-5 secret sharing model).
  - Comprehensive Identity Orchestration (Passwords, TOTP, Passkeys, Secure Notes, Risk Scoring, Breach Detection).

---

## 2. MVP Scope & Milestones

### Phase 1: Core Cryptography & Local-First Storage (Rust Engine)
- [x] Define Master Key Derivation Function (Argon2id) and local encryption scheme (AES-GCM-256 / ChaCha20Poly1305). -> Argon2id (64 MiB, 3 passes) + XChaCha20-Poly1305 in `crates/crypto`.
- [x] Implement local-first encrypted vault storage format (JSON/SQLite encrypted blocks). -> Single JSON envelope with header-bound AEAD in `crates/core`.
- [x] Implement CLI baseline (`init`, `unlock`, `lock`, `export`, `import`). -> `crates/cli`.

### Phase 2: Secret Types & Orchestration Engine
- [ ] Implement item schemas for:
  - [x] Credentials (username, password, URL, notes)
  - [x] TOTP generation and validation (RFC 6238, SHA-1 / 6 digits / 30 s, ±1 step skew)
  - [ ] Passkey / WebAuthn metadata storage
- [x] Implement automated security audit routines (`audit --weak`, duplicate detection, breach check integration mock/API). -> `krypton audit`: weak/common/reused/username-as-password checks, offline denylist (live breach API still pending).

### Phase 3: Device Trust Graph & Local Sync
- [x] Implement device-pairing handshake (ED25519 keypairs per device bound to local TPM/secure enclave where available). -> ED25519 identities and a signed two-message invite/accept handshake with nonce binding (`krypton device init|invite|accept|complete|list`). TPM/secure-enclave binding still pending.
- [ ] Establish trust graph state structure (signed peer certificates/trust lists). -> Public device records live in the vault body and are filled by the pairing handshake; signed/revocable edges and cross-device replication pending.
- [x] Implement encrypted synchronization payloads between trusted devices. -> `krypton sync export|import`: HKDF-derived key over the vault key and both device keys, sender signature, whole-body last-write-wins merge. Transport and CRDT merging pending.

### Phase 4: CLI / TUI Interface
- [ ] Build a responsive Terminal User Interface (TUI) using Ratatui for interactive navigation.
- [ ] Implement robust CLI commands matching modern workflow needs (`warden vault ls`, `warden generate`, `warden audit`). -> `init`, `add` (credential/note/totp), `show`, `remove`, `generate`, `unlock`, `lock`, `change-password`, `export`, `import`, `device`, `sync`, `audit`, `totp` exist; edit-in-place and the TUI are still missing.

### Phase 5: Trustless Sharing & Threshold Recovery
- [ ] Implement shareable access token generation with expiration (TTL) and granular permission scopes.
- [ ] Implement Shamir's Secret Sharing (or threshold cryptography) for social recovery models (e.g., $m$-of-$n$ guardian setup).

---

## 3. Agent Execution & Task Breakdown

### Milestone 1 Tasks (Done)
1. **Repository Setup:** Initialize Cargo workspace with modular crates (`core`, `crypto`, `cli`, `tui`).
2. **Encryption Module:** Write robust serialization and authenticated encryption wrappers in Rust.
3. **CLI Parser:** Setup command-line argument routing using `clap`.

### Next Up
- Phase 2: item schemas beyond the initial model (TOTP generation, passkey metadata) and `audit` routines.
- Password rotation (`change-password`) and vault metadata in the header.
- Phase 4 TUI (`crates/tui` is a placeholder today).
