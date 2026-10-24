// SPDX-License-Identifier: AGPL-3.0-or-later
//! `krypton` - command-line front end for the local-first encrypted vault.

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use krypton_core::device::{DeviceKey, DeviceRecord, device_key_path};
use krypton_core::{Item, ItemKind, Vault, pairing, totp as totp_code};

/// Where the vault lives unless `--vault` / `KRYPTON_VAULT` says otherwise.
const DEFAULT_DIR: &str = ".krypton";
const DEFAULT_FILE: &str = "vault.kv";

#[derive(Parser)]
#[command(
    name = "krypton",
    version,
    about = "Local-first, zero-knowledge encrypted vault",
    long_about = "Encrypted vault with an Argon2id-derived key and XChaCha20-Poly1305 \
                  authenticated encryption. Nothing leaves the machine."
)]
struct Cli {
    /// Vault file to operate on
    #[arg(long, global = true, env = "KRYPTON_VAULT", value_name = "PATH")]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new encrypted vault
    Init {
        /// Replace an existing vault at this path
        #[arg(long)]
        force: bool,
    },

    /// Verify the master password and list the decrypted items
    Unlock,

    /// Re-encrypt the vault with a fresh nonce
    Lock,

    /// Re-derive the vault key from a new master password
    ChangePassword,

    /// Check credentials for weak, common and reused passwords
    Audit,

    /// Generate a strong random password
    Generate {
        /// Number of characters
        #[arg(long, default_value_t = krypton_core::password::DEFAULT_LENGTH)]
        length: usize,
        /// Letters and digits only, no symbols
        #[arg(long)]
        no_symbols: bool,
    },

    /// Add a credential, note or TOTP seed to the vault
    Add {
        #[command(subcommand)]
        item: AddCommand,
    },

    /// Manage this device's Ed25519 identity
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },

    /// Generate a TOTP code for an item
    Totp {
        /// Item title (case-insensitive substring) or id prefix
        query: String,
        /// Unix time to generate the code for (defaults to now)
        #[arg(long, value_name = "UNIX")]
        at: Option<u64>,
    },

    /// Send or receive an encrypted vault update for a paired device
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },

    /// Write the decrypted contents to a plaintext JSON file
    Export {
        /// Destination file (written with owner-only permissions)
        #[arg(long = "out", value_name = "PATH")]
        output: PathBuf,
        /// Overwrite the destination if it exists
        #[arg(long)]
        force: bool,
    },

    /// Seal a plaintext JSON body into a new vault
    Import {
        /// Plaintext JSON body: {"items": [...]}
        #[arg(long = "in", value_name = "PATH")]
        input: PathBuf,
        /// Replace an existing vault at this path
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let path = match cli.vault {
        Some(path) => path,
        None => default_vault_path()?,
    };

    match cli.command {
        Command::Init { force } => init(&path, force),
        Command::Unlock => unlock(&path),
        Command::Lock => lock(&path),
        Command::ChangePassword => change_password(&path),
        Command::Audit => audit(&path),
        Command::Add { item } => add(&path, item),
        Command::Generate { length, no_symbols } => generate(length, !no_symbols),
        Command::Totp { query, at } => totp(&path, &query, at),
        Command::Export { output, force } => export(&path, &output, force),
        Command::Import { input, force } => import(&path, &input, force),
        Command::Device { command } => device(&path, command),
        Command::Sync { command } => sync(&path, command),
    }
}

#[derive(Subcommand)]
enum AddCommand {
    /// Store a username/password pair
    Credential {
        /// Label shown in listings
        #[arg(long)]
        title: String,
        /// Login name
        #[arg(long)]
        username: String,
        /// Password to store; prompted for (hidden) when omitted
        #[arg(long, value_name = "PASSWORD")]
        password: Option<String>,
        /// Site or service URL
        #[arg(long)]
        url: Option<String>,
        /// Free-form notes
        #[arg(long)]
        notes: Option<String>,
    },

    /// Store free-form text
    Note {
        /// Label shown in listings
        #[arg(long)]
        title: String,
        /// Note contents
        #[arg(long)]
        body: String,
    },

    /// Store an authenticator (TOTP) seed
    Totp {
        /// Label shown in listings
        #[arg(long)]
        title: String,
        /// Base32 shared secret from the issuer
        #[arg(long)]
        secret: String,
        /// Service that issued the seed
        #[arg(long)]
        issuer: Option<String>,
        /// Account name the seed belongs to
        #[arg(long)]
        account: Option<String>,
    },
}

#[derive(Subcommand)]
enum SyncCommand {
    /// Seal the vault body for a trusted device
    Export {
        /// Trusted device name, fingerprint or public key
        #[arg(long, value_name = "PEER")]
        to: String,
        /// Destination file for the sealed payload
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        /// Overwrite the destination if it exists
        #[arg(long)]
        force: bool,
    },

    /// Verify and merge a payload produced by a trusted device
    Import {
        /// Payload file produced by `krypton sync export`
        #[arg(long = "in", value_name = "PATH")]
        input: PathBuf,
    },
}

#[derive(Subcommand)]
enum DeviceCommand {
    /// Create a signing key for this device and register its public key
    Init {
        /// Friendly device name shown in the trust list
        #[arg(long, value_name = "NAME")]
        name: String,
        /// Replace an existing device key and re-register this device
        #[arg(long)]
        force: bool,
    },

    /// List the devices registered in the vault
    List,

    /// Print a signed invite for another device to accept
    Invite,

    /// Verify an invite and print the acceptance blob for its owner
    Accept {
        /// Invite blob printed by the other device
        #[arg(long, value_name = "BLOB")]
        invite: String,
        /// Name to register this device under (defaults to its trust-list name)
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
    },

    /// Verify the peer's acceptance and add it to the trust list
    Complete {
        /// The invite blob this device printed
        #[arg(long, value_name = "BLOB")]
        invite: String,
        /// Acceptance blob printed by the other device
        #[arg(long, value_name = "BLOB")]
        response: String,
    },
}

fn generate(length: usize, include_symbols: bool) -> Result<()> {
    println!(
        "{}",
        krypton_core::password::generate(length, include_symbols)?
    );
    Ok(())
}

fn add(path: &Path, command: AddCommand) -> Result<()> {
    let password = read_password("Master password: ")?;
    let mut vault = Vault::open(path, &password)?;

    let (title, kind) = match command {
        AddCommand::Credential {
            title,
            username,
            password,
            url,
            notes,
        } => {
            let password = match password {
                Some(password) => password,
                None => read_password("Password to store: ")?,
            };
            if password.is_empty() {
                bail!("stored password must not be empty");
            }
            (
                title,
                ItemKind::Credential {
                    username,
                    password,
                    url,
                    notes,
                },
            )
        }

        AddCommand::Note { title, body } => (title, ItemKind::Note { body }),

        AddCommand::Totp {
            title,
            secret,
            issuer,
            account,
        } => {
            // Reject a mistyped seed now instead of sealing it into the vault.
            if let Err(err) = totp_code::generate(&secret, 0) {
                bail!("invalid TOTP secret: {err}");
            }
            (
                title,
                ItemKind::Totp {
                    secret,
                    issuer,
                    account,
                },
            )
        }
    };

    if title.trim().is_empty() {
        bail!("item title must not be empty");
    }
    let item = Item::new(title, kind)?;
    let short_id = item.id[..8].to_string();
    let label = item.kind_label();
    vault.items_mut().push(item);
    vault.save()?;

    println!(
        "Added {label} (id {short_id}) to {}",
        vault.path().display()
    );
    Ok(())
}

fn device(path: &Path, command: DeviceCommand) -> Result<()> {
    let key_path = device_key_path(path);

    match command {
        DeviceCommand::Init { name, force } => device_init(path, &key_path, name, force),
        DeviceCommand::List => device_list(path, &key_path),
        DeviceCommand::Invite => device_invite(path, &key_path),
        DeviceCommand::Accept { invite, name } => {
            device_accept(path, &key_path, &invite, name.as_deref())
        }
        DeviceCommand::Complete { invite, response } => {
            device_complete(path, &key_path, &invite, &response)
        }
    }
}

fn device_init(path: &Path, key_path: &Path, name: String, force: bool) -> Result<()> {
    if key_path.exists() && !force {
        bail!(
            "{} already holds a device key; pass --force to replace it",
            key_path.display()
        );
    }

    let password = read_password("Master password: ")?;
    let mut vault = Vault::open(path, &password)?;

    // A replaced key leaves a stale record behind: drop it so the trust
    // list only names identities that still exist somewhere.
    let previous = DeviceKey::load(key_path).ok().map(|key| key.public_key());

    let key = DeviceKey::generate()?;
    key.save(key_path)?;

    let record = DeviceRecord::new(name, &key);
    vault
        .devices_mut()
        .retain(|existing| Some(&existing.public_key) != previous.as_ref());
    vault
        .devices_mut()
        .retain(|existing| existing.public_key != record.public_key);
    vault.devices_mut().push(record.clone());
    vault.save()?;

    println!("Device registered as {:?}", record.name);
    println!("  fingerprint: {}", record.fingerprint());
    println!("  key file:    {}", key_path.display());
    Ok(())
}

fn device_list(path: &Path, key_path: &Path) -> Result<()> {
    let password = read_password("Master password: ")?;
    let vault = Vault::open(path, &password)?;

    let local_key = DeviceKey::load(key_path).ok();
    let local_public = local_key.as_ref().map(DeviceKey::public_key);

    if vault.devices().is_empty() {
        println!("No devices registered in {}", vault.path().display());
        return Ok(());
    }

    println!(
        "{} device(s) in {}",
        vault.devices().len(),
        vault.path().display()
    );
    for device in vault.devices() {
        let marker = if local_public.as_deref() == Some(device.public_key.as_str()) {
            "*"
        } else {
            " "
        };
        println!(" {marker} {:<20} {}", device.name, device.fingerprint());
    }
    if local_key.is_none() {
        println!("   (no local device key at {})", key_path.display());
    }
    Ok(())
}

fn device_invite(path: &Path, key_path: &Path) -> Result<()> {
    let key = load_local_key(key_path)?;

    let password = read_password("Master password: ")?;
    let vault = Vault::open(path, &password)?;
    let name = local_device_name(&vault, &key).unwrap_or_else(|| "krypton-device".to_string());

    let blob = pairing::create_invite(&name, &key)?;
    println!(
        "Invite for {name:?} ({}) on {}:",
        key.fingerprint(),
        key_path.display()
    );
    println!("{blob}");
    println!();
    println!(
        "Send this blob to the other device and run there:\n  krypton device accept --invite <blob>"
    );
    Ok(())
}

fn device_accept(path: &Path, key_path: &Path, invite: &str, name: Option<&str>) -> Result<()> {
    let key = load_local_key(key_path)?;
    let invite = pairing::parse_invite(invite)?;
    if invite.public_key == key.public_key() {
        bail!("this invite belongs to the current device");
    }

    let password = read_password("Master password: ")?;
    let mut vault = Vault::open(path, &password)?;

    let name = name
        .map(str::to_string)
        .or_else(|| local_device_name(&vault, &key))
        .unwrap_or_else(|| "krypton-device".to_string());

    let acceptance = pairing::create_acceptance(&invite, &name, &key)?;
    remember_device(&mut vault, invite.record());
    vault.save()?;

    println!(
        "Added {:?} ({}) to the trust list",
        invite.name,
        invite.record().fingerprint()
    );
    println!(
        "Compare that fingerprint with {:?} out of band before relying on it.",
        invite.name
    );
    println!();
    println!("Acceptance for {:?}:", invite.name);
    println!("{acceptance}");
    Ok(())
}

fn device_complete(path: &Path, key_path: &Path, invite: &str, response: &str) -> Result<()> {
    let key = load_local_key(key_path)?;
    let invite = pairing::parse_invite(invite)?;
    let acceptance = pairing::parse_acceptance(response, &invite)?;
    if acceptance.public_key == key.public_key() {
        bail!("the acceptance came from this device");
    }

    let password = read_password("Master password: ")?;
    let mut vault = Vault::open(path, &password)?;

    remember_device(&mut vault, acceptance.record());
    vault.save()?;

    println!(
        "Paired with {:?} ({})",
        acceptance.name,
        acceptance.record().fingerprint()
    );
    println!("Both devices now hold each other's public key.");
    Ok(())
}

fn load_local_key(key_path: &Path) -> Result<DeviceKey> {
    DeviceKey::load(key_path).with_context(|| {
        format!(
            "no usable device key at {}; run `krypton device init --name <name>` first",
            key_path.display()
        )
    })
}

fn local_device_name(vault: &Vault, key: &DeviceKey) -> Option<String> {
    let public_key = key.public_key();
    vault
        .devices()
        .iter()
        .find(|device| device.public_key == public_key)
        .map(|device| device.name.clone())
}

fn remember_device(vault: &mut Vault, record: DeviceRecord) {
    vault
        .devices_mut()
        .retain(|existing| existing.public_key != record.public_key);
    vault.devices_mut().push(record);
}

fn sync(path: &PathBuf, command: SyncCommand) -> Result<()> {
    let key_path = device_key_path(path);
    let key = load_local_key(&key_path)?;

    match command {
        SyncCommand::Export { to, out, force } => {
            if out.exists() && !force {
                bail!(
                    "{} already exists; pass --force to overwrite it",
                    out.display()
                );
            }

            let password = read_password("Master password: ")?;
            let vault = Vault::open(path, &password)?;
            let peer = find_peer(&vault, &to)?;

            let payload = krypton_core::sync::create_payload(&vault, &key, &peer.public_key)?;
            write_secret_file(&out, &payload)?;

            println!(
                "Sealed {} for {:?} ({}) into {}",
                item_count(vault.items().len()),
                peer.name,
                peer.fingerprint(),
                out.display()
            );
            Ok(())
        }

        SyncCommand::Import { input } => {
            let password = read_password("Master password: ")?;
            let mut vault = Vault::open(path, &password)?;

            let bytes = std::fs::read(&input)
                .with_context(|| format!("could not read {}", input.display()))?;
            let incoming = krypton_core::sync::read_payload(&vault, &key, &bytes)?;
            let stats = krypton_core::sync::merge(vault.body_mut(), incoming.body);
            vault.save()?;

            println!(
                "Applied payload from {:?} ({}): {} added, {} updated, {} new device(s)",
                incoming.sender.name,
                incoming.sender.fingerprint(),
                stats.items_added,
                stats.items_updated,
                stats.devices_added
            );
            println!("Vault now holds {}", item_count(vault.items().len()));
            Ok(())
        }
    }
}

fn find_peer<'a>(vault: &'a Vault, query: &str) -> Result<&'a DeviceRecord> {
    let query_lower = query.to_ascii_lowercase();
    let peer = vault.devices().iter().find(|device| {
        device.name.to_ascii_lowercase() == query_lower
            || device.public_key == query
            || device.fingerprint().starts_with(&query_lower)
    });

    if let Some(peer) = peer {
        Ok(peer)
    } else {
        let known: Vec<&str> = vault
            .devices()
            .iter()
            .map(|device| device.name.as_str())
            .collect();
        if known.is_empty() {
            bail!("no devices are paired yet; run `krypton device invite` first");
        }
        bail!(
            "no trusted device matches {query:?}; known devices: {}",
            known.join(", ")
        );
    }
}

fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn init(path: &PathBuf, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; pass --force to replace it",
            path.display()
        );
    }
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("could not replace {}", path.display()))?;
    }

    let password = read_new_password("Master password")?;
    let vault = Vault::create(path, &password)?;

    println!("Initialized empty vault at {}", vault.path().display());
    println!("Guard the master password: it is the only way back in.");
    Ok(())
}

fn unlock(path: &PathBuf) -> Result<()> {
    let password = read_password("Master password: ")?;
    let vault = Vault::open(path, &password)?;

    let items = vault.items();
    println!(
        "Unlocked {} ({} item{})",
        vault.path().display(),
        items.len(),
        if items.len() == 1 { "" } else { "s" }
    );

    for item in items {
        let detail = match &item.kind {
            ItemKind::Credential { username, url, .. } => url
                .as_ref()
                .map_or_else(|| username.clone(), |url| format!("{username} <{url}>")),
            ItemKind::Totp {
                issuer, account, ..
            } => match (issuer, account) {
                (Some(issuer), Some(account)) => format!("{issuer} / {account}"),
                (Some(issuer), None) => issuer.clone(),
                (None, Some(account)) => account.clone(),
                (None, None) => String::new(),
            },
            ItemKind::Note { body } => format!("{} chars", body.chars().count()),
        };
        println!("  [{}] {:<24} {}", item.kind_label(), item.title, detail);
    }

    Ok(())
}

/// Re-seals the vault, which rotates the nonce. There is no long-lived session
/// to drop: every command derives the key from the password and exits.
fn lock(path: &PathBuf) -> Result<()> {
    let password = read_password("Master password: ")?;
    let vault = Vault::open(path, &password)?;
    vault.save()?;
    println!("Re-sealed {} with a fresh nonce", vault.path().display());
    Ok(())
}

fn change_password(path: &PathBuf) -> Result<()> {
    let current = read_password("Current master password: ")?;
    let mut vault = Vault::open(path, &current)?;

    let new_password = read_new_password("New master password")?;
    vault.change_password(&new_password)?;

    println!(
        "Master password changed for {} (fresh salt, fresh nonce)",
        vault.path().display()
    );
    Ok(())
}

fn audit(path: &PathBuf) -> Result<()> {
    let password = read_password("Master password: ")?;
    let vault = Vault::open(path, &password)?;

    let findings = krypton_core::audit::audit(vault.items());
    if findings.is_empty() {
        println!(
            "No issues found across {} in {}",
            item_count(vault.items().len()),
            vault.path().display()
        );
        return Ok(());
    }

    println!(
        "{} finding(s) across {} in {}",
        findings.len(),
        item_count(vault.items().len()),
        vault.path().display()
    );
    for finding in &findings {
        println!(
            "  [{:<6}] {:<22} {}",
            finding.severity.label(),
            finding.title,
            finding.message
        );
    }

    Ok(())
}

fn totp(path: &PathBuf, query: &str, at: Option<u64>) -> Result<()> {
    if query.trim().is_empty() {
        bail!("pass an item title or id to generate a code for");
    }

    let password = read_password("Master password: ")?;
    let vault = Vault::open(path, &password)?;

    let needle = query.to_ascii_lowercase();
    let item = vault
        .items()
        .iter()
        .find(|item| {
            item.id.starts_with(query) || item.title.to_ascii_lowercase().contains(&needle)
        })
        .with_context(|| format!("no item matching {query:?} in {}", vault.path().display()))?;

    let ItemKind::Totp { secret, .. } = &item.kind else {
        bail!(
            "{} is a {} item, not a TOTP item",
            item.title,
            item.kind_label()
        );
    };

    let now = at.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or_default()
    });

    let code = totp_code::generate(secret, now)?;
    println!(
        "{}  {}  ({}s remaining)",
        item.title,
        code,
        totp_code::seconds_remaining(now)
    );
    Ok(())
}

fn export(path: &PathBuf, output: &PathBuf, force: bool) -> Result<()> {
    if output.exists() && !force {
        bail!(
            "{} already exists; pass --force to overwrite it",
            output.display()
        );
    }

    let password = read_password("Master password: ")?;
    let vault = Vault::open(path, &password)?;
    vault.export_plaintext(output)?;

    eprintln!(
        "WARNING: {} holds decrypted secrets in plaintext. Delete it once done.",
        output.display()
    );
    println!(
        "Exported {} items to {}",
        vault.items().len(),
        output.display()
    );
    Ok(())
}

fn import(path: &PathBuf, input: &PathBuf, force: bool) -> Result<()> {
    if path.exists() && !force {
        bail!(
            "{} already exists; pass --force to replace it",
            path.display()
        );
    }
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("could not replace {}", path.display()))?;
    }

    let password = read_new_password("Master password")?;
    let vault = Vault::import_plaintext(input, path, &password)?;

    println!(
        "Imported {} items into {}",
        vault.items().len(),
        vault.path().display()
    );
    Ok(())
}

fn item_count(count: usize) -> String {
    if count == 1 {
        "1 item".to_string()
    } else {
        format!("{count} items")
    }
}

fn default_vault_path() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("KRYPTON_HOME") {
        return Ok(PathBuf::from(dir).join(DEFAULT_FILE));
    }
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home).join(DEFAULT_DIR).join(DEFAULT_FILE));
    }
    bail!("cannot determine a vault location; pass --vault PATH or set KRYPTON_HOME")
}

/// Reads one password line. Interactive terminals get a hidden prompt; piped
/// input (scripts, tests) is read verbatim up to the newline.
fn read_password(prompt: &str) -> Result<String> {
    if io::stdin().is_terminal() {
        return Ok(rpassword::prompt_password(prompt)?);
    }

    let mut line = String::new();
    let read = io::stdin().read_line(&mut line)?;
    if read == 0 {
        bail!("no password provided on stdin");
    }
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Reads and confirms a new master password (two lines when piped).
fn read_new_password(label: &str) -> Result<String> {
    let (first, second) = if io::stdin().is_terminal() {
        (
            rpassword::prompt_password(format!("{label}: "))?,
            rpassword::prompt_password(format!("Confirm {label}: "))?,
        )
    } else {
        (read_password("")?, read_password("")?)
    };

    if first.is_empty() {
        bail!("master password must not be empty");
    }
    if first != second {
        bail!("passwords do not match");
    }
    Ok(first)
}
