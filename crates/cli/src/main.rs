// SPDX-License-Identifier: AGPL-3.0-or-later
//! `krypton` - command-line front end for the local-first encrypted vault.

use std::io::{self, IsTerminal};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use krypton_core::device::{DeviceKey, DeviceRecord, device_key_path};
use krypton_core::{ItemKind, Vault, totp as totp_code};

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
        Command::Totp { query, at } => totp(&path, &query, at),
        Command::Export { output, force } => export(&path, &output, force),
        Command::Import { input, force } => import(&path, &input, force),
        Command::Device { command } => device(&path, command),
    }
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
}

fn device(path: &PathBuf, command: DeviceCommand) -> Result<()> {
    let key_path = device_key_path(path);

    match command {
        DeviceCommand::Init { name, force } => {
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
            let previous = DeviceKey::load(&key_path).ok().map(|key| key.public_key());

            let key = DeviceKey::generate()?;
            key.save(&key_path)?;

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

        DeviceCommand::List => {
            let password = read_password("Master password: ")?;
            let vault = Vault::open(path, &password)?;

            let local_key = DeviceKey::load(&key_path).ok();
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
    }
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
            ItemKind::Credential { username, url, .. } => match url {
                Some(url) => format!("{username} <{url}>"),
                None => username.clone(),
            },
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
