// SPDX-License-Identifier: AGPL-3.0-or-later
//! Offline health checks for credential items: weak, common and reused
//! passwords. No network calls - a breach API can be layered on later.

use std::collections::HashMap;

use crate::{Item, ItemKind};

/// Passwords shorter than this are reported as weak.
pub const MIN_PASSWORD_LEN: usize = 12;

/// Small offline denylist of passwords that show up in every breach dump.
const COMMON_PASSWORDS: &[&str] = &[
    "123456",
    "12345678",
    "123456789",
    "111111",
    "000000",
    "123123",
    "abc123",
    "admin",
    "baseball",
    "dragon",
    "football",
    "hunter2",
    "iloveyou",
    "letmein",
    "master",
    "monkey",
    "password",
    "password1",
    "passw0rd",
    "qwerty",
    "qwerty123",
    "sunshine",
    "trustno1",
    "welcome",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Medium,
    High,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub item_id: String,
    pub title: String,
    pub severity: Severity,
    pub message: String,
}

/// Checks every credential item and returns findings, most severe first.
pub fn audit(items: &[Item]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut password_uses: HashMap<&str, Vec<&str>> = HashMap::new();

    for item in items {
        let ItemKind::Credential {
            username, password, ..
        } = &item.kind
        else {
            continue;
        };
        if password.is_empty() {
            continue;
        }

        password_uses
            .entry(password.as_str())
            .or_default()
            .push(item.title.as_str());

        if password.chars().count() < MIN_PASSWORD_LEN {
            findings.push(Finding {
                item_id: item.id.clone(),
                title: item.title.clone(),
                severity: Severity::Medium,
                message: format!(
                    "password is shorter than {MIN_PASSWORD_LEN} characters ({} characters)",
                    password.chars().count()
                ),
            });
        }

        let normalized = password.trim().to_ascii_lowercase();
        if COMMON_PASSWORDS.contains(&normalized.as_str()) {
            findings.push(Finding {
                item_id: item.id.clone(),
                title: item.title.clone(),
                severity: Severity::High,
                message: "password appears in common breach lists".to_string(),
            });
        }

        if !username.is_empty() && username.eq_ignore_ascii_case(password) {
            findings.push(Finding {
                item_id: item.id.clone(),
                title: item.title.clone(),
                severity: Severity::High,
                message: "password is identical to the username".to_string(),
            });
        }
    }

    for (password, titles) in password_uses {
        if titles.len() < 2 {
            continue;
        }
        let message = format!(
            "password is reused across {} items: {}",
            titles.len(),
            titles.join(", ")
        );
        for item in items {
            if let ItemKind::Credential {
                password: item_password,
                ..
            } = &item.kind
                && item_password == password
            {
                findings.push(Finding {
                    item_id: item.id.clone(),
                    title: item.title.clone(),
                    severity: Severity::High,
                    message: message.clone(),
                });
            }
        }
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.title.cmp(&b.title))
            .then_with(|| a.message.cmp(&b.message))
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ItemKind;

    fn credential(title: &str, username: &str, password: &str) -> Item {
        Item::new(
            title,
            ItemKind::Credential {
                username: username.into(),
                password: password.into(),
                url: None,
                notes: None,
            },
        )
        .unwrap()
    }

    #[test]
    fn strong_unique_passwords_produce_no_findings() {
        let items = vec![
            credential("mail", "me", "zG7!pQ2vLx#9wR4t"),
            credential("bank", "me", "Kd8$mN3yBv!6sX1c"),
        ];
        assert!(audit(&items).is_empty());
    }

    #[test]
    fn short_passwords_are_medium_severity() {
        let items = vec![credential("mail", "me", "short")];
        let findings = audit(&items);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::Medium);
        assert!(findings[0].message.contains("shorter than 12"));
    }

    #[test]
    fn common_passwords_are_high_severity() {
        let items = vec![credential("legacy", "me", "Password")];
        let findings = audit(&items);
        assert!(
            findings
                .iter()
                .any(|f| f.severity == Severity::High && f.message.contains("common breach lists"))
        );
    }

    #[test]
    fn username_as_password_is_flagged() {
        let items = vec![credential("router", "admin", "admin")];
        let findings = audit(&items);
        assert!(
            findings
                .iter()
                .any(|f| f.message.contains("identical to the username"))
        );
    }

    #[test]
    fn reused_passwords_are_reported_for_every_item() {
        let items = vec![
            credential("mail", "me", "zG7!pQ2vLx#9wR4t"),
            credential("shop", "me", "zG7!pQ2vLx#9wR4t"),
        ];
        let findings = audit(&items);
        assert_eq!(findings.len(), 2);
        assert!(
            findings
                .iter()
                .all(|f| f.severity == Severity::High && f.message.contains("mail, shop"))
        );
    }

    #[test]
    fn high_severity_findings_come_first() {
        let items = vec![
            credential("weak", "me", "short"),
            credential("leaked", "me", "letmein"),
        ];
        let findings = audit(&items);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn non_credential_items_are_ignored() {
        let items = vec![
            Item::new(
                "code",
                ItemKind::Note {
                    body: "123456".into(),
                },
            )
            .unwrap(),
            Item::new(
                "totp",
                ItemKind::Totp {
                    secret: "GEZDGNBVGY3TQOJQ".into(),
                    issuer: None,
                    account: None,
                },
            )
            .unwrap(),
        ];
        assert!(audit(&items).is_empty());
    }
}
