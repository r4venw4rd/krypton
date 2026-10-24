// SPDX-License-Identifier: AGPL-3.0-or-later
//! TUI state machine.
//!
//! All vault interaction lives here, free of terminal I/O, so the behaviour can
//! be tested without a real terminal.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use krypton_core::{Item, ItemKind, Vault};

/// Which screen the interface is showing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    /// Password entry before the vault can be read.
    Locked,
    /// Item browser.
    Unlocked,
}

/// Application state driven by key events.
#[derive(Debug)]
pub struct App {
    vault_path: PathBuf,
    password: String,
    screen: Screen,
    error: Option<String>,
    vault: Option<Vault>,
    selected: usize,
    reveal: bool,
}

impl App {
    /// Creates a locked app for the vault at `vault_path`.
    pub fn new(vault_path: impl Into<PathBuf>) -> Self {
        Self {
            vault_path: vault_path.into(),
            password: String::new(),
            screen: Screen::Locked,
            error: None,
            vault: None,
            selected: 0,
            reveal: false,
        }
    }

    /// Vault file being browsed.
    #[must_use]
    pub fn vault_path(&self) -> &Path {
        &self.vault_path
    }

    /// Current screen.
    #[must_use]
    pub const fn screen(&self) -> Screen {
        self.screen
    }

    /// Last unlock error, if any.
    #[must_use]
    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    /// Number of characters typed into the password field.
    #[must_use]
    pub fn password_len(&self) -> usize {
        self.password.chars().count()
    }

    /// Items in the unlocked vault.
    #[must_use]
    pub fn items(&self) -> &[Item] {
        self.vault.as_ref().map_or(&[], Vault::items)
    }

    /// Index of the highlighted item.
    #[must_use]
    pub const fn selected(&self) -> usize {
        self.selected
    }

    /// Item under the cursor.
    #[must_use]
    pub fn selected_item(&self) -> Option<&Item> {
        self.items().get(self.selected)
    }

    /// Whether secrets are currently shown.
    #[must_use]
    pub const fn reveal(&self) -> bool {
        self.reveal
    }

    /// Appends a character to the password field while locked.
    pub fn push_char(&mut self, character: char) {
        if self.screen == Screen::Locked {
            self.password.push(character);
            self.error = None;
        }
    }

    /// Removes the last password character while locked.
    pub fn backspace(&mut self) {
        if self.screen == Screen::Locked {
            self.password.pop();
            self.error = None;
        }
    }

    /// Tries to unlock the vault, recording any failure for the UI.
    pub fn unlock(&mut self) {
        match Vault::open(&self.vault_path, &self.password) {
            Ok(vault) => {
                self.vault = Some(vault);
                self.screen = Screen::Unlocked;
                self.selected = 0;
                self.reveal = false;
                self.error = None;
                self.password.clear();
            }
            Err(err) => self.error = Some(err.to_string()),
        }
    }

    /// Moves the selection down, wrapping at the end.
    pub fn next(&mut self) {
        let len = self.items().len();
        if len > 0 {
            self.selected = (self.selected + 1) % len;
        }
    }

    /// Moves the selection up, wrapping at the start.
    pub fn previous(&mut self) {
        let len = self.items().len();
        if len > 0 {
            self.selected = (self.selected + len - 1) % len;
        }
    }

    /// Shows or hides secrets in the detail pane.
    pub const fn toggle_reveal(&mut self) {
        self.reveal = !self.reveal;
    }

    /// Lines rendered in the detail pane.
    #[must_use]
    pub fn detail_lines(&self) -> Vec<String> {
        let Some(item) = self.selected_item() else {
            return vec!["No items in this vault.".to_string()];
        };

        let mut lines = vec![
            format!("title:  {}", item.title),
            format!("type:   {}", item.kind_label()),
        ];

        match &item.kind {
            ItemKind::Credential {
                username,
                password,
                url,
                notes,
            } => {
                lines.push(format!("user:   {username}"));
                lines.push(format!("pass:   {}", self.mask(password)));
                if let Some(url) = url {
                    lines.push(format!("url:    {url}"));
                }
                if let Some(notes) = notes {
                    lines.push(format!("notes:  {}", self.mask(notes)));
                }
            }
            ItemKind::Totp {
                secret,
                issuer,
                account,
            } => {
                if let Some(issuer) = issuer {
                    lines.push(format!("issuer: {issuer}"));
                }
                if let Some(account) = account {
                    lines.push(format!("account:{account}"));
                }
                lines.push(format!("secret: {}", self.mask(secret)));
                if self.reveal
                    && let Ok(code) = krypton_core::totp::generate(secret, now_unix())
                {
                    lines.push(format!(
                        "code:   {code} ({}s left)",
                        krypton_core::totp::seconds_remaining(now_unix())
                    ));
                }
            }
            ItemKind::Note { body } => {
                if self.reveal {
                    lines.push(String::new());
                    lines.push(body.clone());
                } else {
                    lines.push("(hidden; press r to reveal)".to_string());
                }
            }
        }

        lines
    }

    fn mask(&self, value: &str) -> String {
        if self.reveal {
            value.to_string()
        } else {
            "*".repeat(value.chars().count().min(32))
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use krypton_core::{KdfParams, Vault};

    struct Fixture {
        dir: PathBuf,
        path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            use std::sync::atomic::{AtomicUsize, Ordering};

            static NEXT: AtomicUsize = AtomicUsize::new(0);

            let mut dir = std::env::temp_dir();
            dir.push(format!(
                "krypton-tui-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("vault.kv");

            let mut vault =
                Vault::create_with_params(&path, "tui-password", KdfParams::weak_for_tests())
                    .expect("create vault");
            vault.items_mut().push(
                Item::new(
                    "github",
                    ItemKind::Credential {
                        username: "r4venw4rd".into(),
                        password: "s3cret".into(),
                        url: Some("https://github.com".into()),
                        notes: None,
                    },
                )
                .unwrap(),
            );
            vault.items_mut().push(
                Item::new(
                    "notes",
                    ItemKind::Note {
                        body: "private".into(),
                    },
                )
                .unwrap(),
            );
            vault.save().unwrap();

            Self { dir, path }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn unlocked_app() -> (Fixture, App) {
        let fixture = Fixture::new();
        let mut app = App::new(&fixture.path);
        for character in "tui-password".chars() {
            app.push_char(character);
        }
        app.unlock();
        (fixture, app)
    }

    #[test]
    fn starts_locked_without_items() {
        let fixture = Fixture::new();
        let app = App::new(&fixture.path);
        assert_eq!(app.screen(), Screen::Locked);
        assert!(app.items().is_empty());
        assert!(app.error().is_none());
    }

    #[test]
    fn wrong_password_keeps_the_app_locked() {
        let fixture = Fixture::new();
        let mut app = App::new(&fixture.path);
        for character in "nope".chars() {
            app.push_char(character);
        }
        app.unlock();

        assert_eq!(app.screen(), Screen::Locked);
        assert!(app.error().is_some());
        assert!(app.items().is_empty());
        assert_eq!(app.password_len(), 4);
    }

    #[test]
    fn correct_password_unlocks_and_clears_the_buffer() {
        let (_fixture, app) = unlocked_app();
        assert_eq!(app.screen(), Screen::Unlocked);
        assert_eq!(app.items().len(), 2);
        assert_eq!(app.password_len(), 0);
        assert!(app.error().is_none());
    }

    #[test]
    fn backspace_edits_the_password_field() {
        let fixture = Fixture::new();
        let mut app = App::new(&fixture.path);
        app.push_char('a');
        app.push_char('b');
        app.backspace();
        assert_eq!(app.password_len(), 1);
    }

    #[test]
    fn selection_wraps_in_both_directions() {
        let (_fixture, mut app) = unlocked_app();
        assert_eq!(app.selected(), 0);
        app.next();
        assert_eq!(app.selected(), 1);
        app.next();
        assert_eq!(app.selected(), 0);
        app.previous();
        assert_eq!(app.selected(), 1);
    }

    #[test]
    fn secrets_are_masked_until_revealed() {
        let (_fixture, mut app) = unlocked_app();

        let hidden = app.detail_lines().join("\n");
        assert!(hidden.contains("github"));
        assert!(hidden.contains("r4venw4rd"));
        assert!(!hidden.contains("s3cret"));
        assert!(hidden.contains("***"));

        app.toggle_reveal();
        let shown = app.detail_lines().join("\n");
        assert!(shown.contains("s3cret"));
        assert!(shown.contains("https://github.com"));
    }

    #[test]
    fn notes_are_hidden_until_revealed() {
        let (_fixture, mut app) = unlocked_app();
        app.next();

        let hidden = app.detail_lines().join("\n");
        assert!(hidden.contains("hidden; press r"));
        assert!(!hidden.contains("private"));

        app.toggle_reveal();
        assert!(app.detail_lines().join("\n").contains("private"));
    }
}
