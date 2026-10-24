// SPDX-License-Identifier: AGPL-3.0-or-later
//! `krypton-tui` - interactive browser for the encrypted vault.

mod app;
mod ui;

use std::io::{self, IsTerminal};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind};

use crate::app::{App, Screen};

const DEFAULT_DIR: &str = ".krypton";
const DEFAULT_FILE: &str = "vault.kv";

#[derive(Parser)]
#[command(
    name = "krypton-tui",
    version,
    about = "Interactive terminal browser for a krypton vault"
)]
struct Args {
    /// Vault file to browse
    #[arg(long, env = "KRYPTON_VAULT", value_name = "PATH")]
    vault: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let vault = match args.vault {
        Some(path) => path,
        None => default_vault_path()?,
    };

    if !vault.exists() {
        bail!(
            "no vault at {}; create one with `krypton init`",
            vault.display()
        );
    }
    if !io::stdout().is_terminal() {
        bail!("krypton-tui needs an interactive terminal");
    }

    let mut terminal = ratatui::try_init().context("could not set up the terminal")?;
    let mut app = App::new(vault);

    let result = run(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> Result<()> {
    loop {
        terminal
            .draw(|frame| ui::draw(frame, app))
            .context("could not draw the interface")?;

        let Event::Key(key) = event::read().context("could not read terminal input")? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }

        match (app.screen(), key.code) {
            (_, KeyCode::Esc) | (Screen::Unlocked, KeyCode::Char('q')) => return Ok(()),
            (Screen::Locked, KeyCode::Enter) => app.unlock(),
            (Screen::Locked, KeyCode::Backspace) => app.backspace(),
            (Screen::Locked, KeyCode::Char(character)) => app.push_char(character),
            (Screen::Unlocked, KeyCode::Char('j') | KeyCode::Down) => app.next(),
            (Screen::Unlocked, KeyCode::Char('k') | KeyCode::Up) => app.previous(),
            (Screen::Unlocked, KeyCode::Char('r')) => app.toggle_reveal(),
            _ => {}
        }
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
