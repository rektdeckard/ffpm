use crate::profile::Login;
use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, TableState},
};

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Normal,
    Search,
}

pub struct App {
    logins: Vec<Login>,
    filtered: Vec<usize>,
    filter: String,
    mode: Mode,
    table_state: TableState,
    message: Option<String>,
    profile_name: String,
    revealed: Option<usize>, // index into `logins` of the one revealed password
}

impl App {
    pub fn new(logins: Vec<Login>, profile_name: String) -> Self {
        let filtered: Vec<usize> = (0..logins.len()).collect();
        let mut table_state = TableState::default();
        if !filtered.is_empty() {
            table_state.select(Some(0));
        }
        Self {
            logins,
            filtered,
            filter: String::new(),
            mode: Mode::Normal,
            table_state,
            message: None,
            profile_name,
            revealed: None,
        }
    }

    fn apply_filter(&mut self) {
        let query = self.filter.to_lowercase();
        self.filtered = self
            .logins
            .iter()
            .enumerate()
            .filter(|(_, l)| {
                query.is_empty()
                    || l.hostname.to_lowercase().contains(&query)
                    || l.username.to_lowercase().contains(&query)
            })
            .map(|(i, _)| i)
            .collect();

        // Reset selection
        if self.filtered.is_empty() {
            self.table_state.select(None);
        } else {
            self.table_state.select(Some(0));
        }
    }

    fn selected_login(&self) -> Option<&Login> {
        self.table_state
            .selected()
            .and_then(|i| self.filtered.get(i))
            .map(|&idx| &self.logins[idx])
    }

    fn copy_to_clipboard(&mut self, text: &str, label: &str) {
        match arboard::Clipboard::new().and_then(|mut cb| cb.set_text(text.to_string())) {
            Ok(()) => self.message = Some(format!("{label} copied to clipboard")),
            Err(e) => self.message = Some(format!("clipboard error: {e}")),
        }
    }

    /// Handle a key event. Returns `true` if the app should quit.
    pub fn handle_key(&mut self, key: KeyEvent) -> Result<bool> {
        // Clear message on any keypress
        self.message = None;

        match self.mode {
            Mode::Normal => self.handle_normal(key),
            Mode::Search => self.handle_search(key),
        }
    }

    fn handle_normal(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return Ok(true)
            }
            KeyCode::Char('/') | KeyCode::Char('f') => {
                self.mode = Mode::Search;
            }
            KeyCode::Char('j') | KeyCode::Down => {
                self.move_selection(1);
            }
            KeyCode::Char('k') | KeyCode::Up => {
                self.move_selection(-1);
            }
            KeyCode::Char('g') | KeyCode::Home => {
                if !self.filtered.is_empty() {
                    self.table_state.select(Some(0));
                }
            }
            KeyCode::Char('G') | KeyCode::End => {
                if !self.filtered.is_empty() {
                    self.table_state.select(Some(self.filtered.len() - 1));
                }
            }
            KeyCode::Char('c') => {
                if let Some(login) = self.selected_login().cloned() {
                    self.copy_to_clipboard(&login.password, "Password");
                }
            }
            KeyCode::Char('u') => {
                if let Some(login) = self.selected_login().cloned() {
                    self.copy_to_clipboard(&login.username, "Username");
                }
            }
            KeyCode::Char('y') => {
                if let Some(login) = self.selected_login().cloned() {
                    self.copy_to_clipboard(&login.hostname, "URL");
                }
            }
            KeyCode::Char('p') => {
                // Toggle reveal for the selected login only
                if let Some(&idx) = self.table_state.selected().and_then(|i| self.filtered.get(i))
                {
                    self.revealed = if self.revealed == Some(idx) {
                        None
                    } else {
                        Some(idx)
                    };
                }
            }
            _ => {}
        }
        Ok(false)
    }

    fn handle_search(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Normal;
                self.filter.clear();
                self.apply_filter();
            }
            KeyCode::Enter => {
                self.mode = Mode::Normal;
            }
            KeyCode::Backspace => {
                self.filter.pop();
                self.apply_filter();
            }
            KeyCode::Char(c) => {
                self.filter.push(c);
                self.apply_filter();
            }
            _ => {}
        }
        Ok(false)
    }

    fn move_selection(&mut self, delta: i32) {
        if self.filtered.is_empty() {
            return;
        }
        let current = self.table_state.selected().unwrap_or(0) as i32;
        let next = (current + delta).clamp(0, self.filtered.len() as i32 - 1) as usize;
        self.table_state.select(Some(next));
    }

    pub fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();

        let chunks = Layout::vertical([
            Constraint::Length(3), // search bar
            Constraint::Min(5),   // table
            Constraint::Length(1), // status bar
        ])
        .split(area);

        self.render_search(frame, chunks[0]);
        self.render_table(frame, chunks[1]);
        self.render_status(frame, chunks[2]);
    }

    fn render_search(&self, frame: &mut Frame, area: Rect) {
        let title = format!(" ffpm \u{2502} {} ", self.profile_name);
        let (text, style) = if self.mode == Mode::Search {
            (
                format!("/{}", self.filter),
                Style::default().fg(Color::Yellow),
            )
        } else if self.filter.is_empty() {
            (
                String::from(" Press / to search"),
                Style::default().fg(Color::DarkGray),
            )
        } else {
            (
                format!(" Filter: {}", self.filter),
                Style::default().fg(Color::Cyan),
            )
        };

        let search = Paragraph::new(text).style(style).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(if self.mode == Mode::Search {
                    Color::Yellow
                } else {
                    Color::DarkGray
                }))
                .title(title),
        );
        frame.render_widget(search, area);

        // Show cursor in search mode
        if self.mode == Mode::Search {
            frame.set_cursor_position((
                area.x + 1 + self.filter.len() as u16 + 1, // +1 for border, +1 for '/'
                area.y + 1,
            ));
        }
    }

    fn render_table(&mut self, frame: &mut Frame, area: Rect) {
        let header = Row::new(vec![
            Cell::from("Site").style(Style::default().bold()),
            Cell::from("Username").style(Style::default().bold()),
            Cell::from("Password").style(Style::default().bold()),
        ])
        .bottom_margin(1);

        let rows: Vec<Row> = self
            .filtered
            .iter()
            .map(|&idx| {
                let login = &self.logins[idx];
                let pw = if self.revealed == Some(idx) {
                    login.password.as_str()
                } else {
                    "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}"
                };
                Row::new(vec![
                    Cell::from(login.hostname.as_str()),
                    Cell::from(login.username.as_str()),
                    Cell::from(pw),
                ])
            })
            .collect();

        let count = format!(" {} logins ", self.filtered.len());
        let widths = [
            Constraint::Percentage(40),
            Constraint::Percentage(35),
            Constraint::Percentage(25),
        ];
        let active = self.mode == Mode::Normal;
        let table = Table::new(rows, widths)
            .header(header)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(if active {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::DarkGray)
                    })
                    .title_bottom(count),
            )
            .row_highlight_style(if active {
                Style::default()
                    .bg(Color::Yellow)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .bg(Color::DarkGray)
                    .fg(Color::White)
            })
            .highlight_symbol("\u{25b8} ");

        frame.render_stateful_widget(table, area, &mut self.table_state);

        // Show empty state
        if self.filtered.is_empty() {
            let msg = if self.filter.is_empty() {
                "No saved logins"
            } else {
                "No matches"
            };
            let center = Rect::new(
                area.x + area.width / 2 - msg.len() as u16 / 2,
                area.y + area.height / 2,
                msg.len() as u16,
                1,
            );
            frame.render_widget(Clear, center);
            frame.render_widget(
                Paragraph::new(msg).style(Style::default().fg(Color::DarkGray)),
                center,
            );
        }
    }

    fn render_status(&self, frame: &mut Frame, area: Rect) {
        let text = if let Some(msg) = &self.message {
            Line::from(vec![Span::styled(
                format!(" {msg}"),
                Style::default().fg(Color::Green),
            )])
        } else {
            Line::from(vec![
                Span::styled(" /", Style::default().fg(Color::Yellow)),
                Span::raw(" Search  "),
                Span::styled("c", Style::default().fg(Color::Yellow)),
                Span::raw(" Password  "),
                Span::styled("u", Style::default().fg(Color::Yellow)),
                Span::raw(" Username  "),
                Span::styled("y", Style::default().fg(Color::Yellow)),
                Span::raw(" URL  "),
                Span::styled("p", Style::default().fg(Color::Yellow)),
                Span::raw(" Reveal  "),
                Span::styled("q", Style::default().fg(Color::Yellow)),
                Span::raw(" Quit"),
            ])
        };

        let status = Paragraph::new(text).style(Style::default().bg(Color::Black));
        frame.render_widget(status, area);
    }
}
