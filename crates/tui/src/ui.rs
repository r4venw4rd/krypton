// SPDX-License-Identifier: AGPL-3.0-or-later
//! Rendering for the krypton TUI.

use crate::app::{App, Screen};
use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};

/// Draws the current screen.
pub fn draw(frame: &mut Frame<'_>, app: &App) {
    match app.screen() {
        Screen::Locked => draw_locked(frame, frame.area(), app),
        Screen::Unlocked => draw_unlocked(frame, frame.area(), app),
    }
}

fn draw_locked(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);

    let header = Paragraph::new(Line::from(Span::styled(
        "krypton",
        Style::default().add_modifier(Modifier::BOLD),
    )))
    .block(Block::default().borders(Borders::ALL).title(" vault "));
    frame.render_widget(header, chunks[0]);

    let mut lines = vec![
        Line::from("Encrypted local vault"),
        Line::from(""),
        Line::from(format!(
            "master password: {}{}",
            "*".repeat(app.password_len()),
            "_"
        )),
    ];
    if let Some(error) = app.error() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            error.to_string(),
            Style::default().fg(Color::Red),
        )));
    }

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(" unlock "))
            .wrap(Wrap { trim: false }),
        chunks[1],
    );

    frame.render_widget(
        Paragraph::new("Enter unlock    q/Esc quit").block(Block::default()),
        chunks[2],
    );
}

fn draw_unlocked(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(area);

    let header = Paragraph::new(Line::from(vec![
        Span::styled("krypton", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!(
            "  {}  ({} items)",
            app.vault_path().display(),
            app.items().len()
        )),
    ]))
    .block(Block::default().borders(Borders::ALL).title(" vault "));
    frame.render_widget(header, chunks[0]);

    let body = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(chunks[1]);

    draw_list(frame, body[0], app);
    draw_detail(frame, body[1], app);

    frame.render_widget(
        Paragraph::new("j/k move   r show/hide secrets   q quit").block(Block::default()),
        chunks[2],
    );
}

fn draw_list(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let items: Vec<ListItem<'_>> = app
        .items()
        .iter()
        .map(|item| ListItem::new(format!("{}  {}", item.kind_label(), item.title)))
        .collect();

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(app.selected()));
    }

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" items "))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    frame.render_stateful_widget(list, area, &mut state);
}

fn draw_detail(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let title = if app.reveal() {
        " details (secrets shown) "
    } else {
        " details "
    };

    let lines: Vec<Line<'_>> = app.detail_lines().into_iter().map(Line::from).collect();

    frame.render_widget(
        Paragraph::new(lines)
            .block(Block::default().borders(Borders::ALL).title(title))
            .wrap(Wrap { trim: false }),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::App;
    use krypton_core::{Item, ItemKind, KdfParams, Vault};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                if let Some(cell) = buffer.cell((x, y)) {
                    text.push_str(cell.symbol());
                }
            }
            text.push('\n');
        }
        text
    }

    fn unlocked_app() -> (std::path::PathBuf, App) {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "krypton-tui-render-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.kv");

        let mut vault =
            Vault::create_with_params(&path, "pw", KdfParams::weak_for_tests()).unwrap();
        vault.items_mut().push(
            Item::new(
                "github",
                ItemKind::Note {
                    body: "body".into(),
                },
            )
            .unwrap(),
        );
        vault.save().unwrap();

        let mut app = App::new(&path);
        app.push_char('p');
        app.push_char('w');
        app.unlock();
        (dir, app)
    }

    #[test]
    fn locked_screen_prompts_for_the_password() {
        let mut dir = std::env::temp_dir();
        dir.push(format!("krypton-tui-locked-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let app = App::new(dir.join("vault.kv"));

        let mut terminal = Terminal::new(TestBackend::new(80, 20)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let text = buffer_text(&terminal);

        assert!(text.contains("krypton"));
        assert!(text.contains("master password:"));
        assert!(text.contains("Enter unlock"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unlocked_screen_lists_items_and_masks_secrets() {
        let (dir, app) = unlocked_app();

        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|frame| draw(frame, &app)).unwrap();
        let text = buffer_text(&terminal);

        assert!(text.contains("github"));
        assert!(text.contains("1 items"));
        assert!(text.contains("details"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
