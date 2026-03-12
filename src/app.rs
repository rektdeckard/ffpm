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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortField {
    Site,
    Username,
    Created,
    LastUsed,
    Changed,
    TimesUsed,
}

impl SortField {
    const ALL: &[SortField] = &[
        SortField::Site,
        SortField::Username,
        SortField::LastUsed,
        SortField::Created,
        SortField::Changed,
        SortField::TimesUsed,
    ];

    fn index(self) -> usize {
        Self::ALL.iter().position(|&s| s == self).unwrap_or(0)
    }

    fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % Self::ALL.len()]
    }

    fn default_ascending(self) -> bool {
        matches!(self, SortField::Site | SortField::Username)
    }

    fn label(self) -> &'static str {
        match self {
            SortField::Site => "Site",
            SortField::Username => "Username",
            SortField::LastUsed => "Last Used",
            SortField::Created => "Created",
            SortField::Changed => "Changed",
            SortField::TimesUsed => "Uses",
        }
    }
}

pub struct App {
    logins: Vec<Login>,
    filtered: Vec<usize>,
    filter: String,
    mode: Mode,
    table_state: TableState,
    message: Option<String>,
    profile_name: String,
    revealed: Option<usize>,
    sort_field: SortField,
    sort_ascending: [bool; 6],
}

impl App {
    pub fn new(logins: Vec<Login>, profile_name: String) -> Self {
        let filtered: Vec<usize> = (0..logins.len()).collect();
        let mut table_state = TableState::default();
        if !filtered.is_empty() {
            table_state.select(Some(0));
        }
        let sort_ascending = std::array::from_fn(|i| SortField::ALL[i].default_ascending());
        let mut app = Self {
            logins,
            filtered,
            filter: String::new(),
            mode: Mode::Normal,
            table_state,
            message: None,
            profile_name,
            revealed: None,
            sort_field: SortField::Site,
            sort_ascending,
        };
        app.apply_sort();
        app
    }

    fn sort_asc(&self) -> bool {
        self.sort_ascending[self.sort_field.index()]
    }

    fn apply_sort(&mut self) {
        let logins = &self.logins;
        let field = self.sort_field;
        let asc = self.sort_asc();
        self.filtered.sort_by(|&a, &b| {
            let cmp = match field {
                SortField::Site => logins[a]
                    .hostname
                    .to_lowercase()
                    .cmp(&logins[b].hostname.to_lowercase()),
                SortField::Username => logins[a]
                    .username
                    .to_lowercase()
                    .cmp(&logins[b].username.to_lowercase()),
                SortField::Created => logins[a].time_created.cmp(&logins[b].time_created),
                SortField::LastUsed => logins[a].time_last_used.cmp(&logins[b].time_last_used),
                SortField::Changed => logins[a]
                    .time_password_changed
                    .cmp(&logins[b].time_password_changed),
                SortField::TimesUsed => logins[a].times_used.cmp(&logins[b].times_used),
            };
            if asc { cmp } else { cmp.reverse() }
        });
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

        self.apply_sort();

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

    pub fn handle_key(&mut self, key: KeyEvent) -> Result<bool> {
        self.message = None;

        match self.mode {
            Mode::Normal => self.handle_normal(key),
            Mode::Search => self.handle_search(key),
        }
    }

    fn handle_normal(&mut self, key: KeyEvent) -> Result<bool> {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(true),
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return Ok(true),
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
                if let Some(&idx) = self
                    .table_state
                    .selected()
                    .and_then(|i| self.filtered.get(i))
                {
                    self.revealed = if self.revealed == Some(idx) {
                        None
                    } else {
                        Some(idx)
                    };
                }
            }
            KeyCode::Char('s') => {
                self.sort_field = self.sort_field.next();
                self.apply_sort();
                self.message = Some(format!(
                    "Sort: {} {}",
                    self.sort_field.label(),
                    if self.sort_asc() {
                        "\u{25b2}"
                    } else {
                        "\u{25bc}"
                    }
                ));
            }
            KeyCode::Char('S') => {
                let idx = self.sort_field.index();
                self.sort_ascending[idx] = !self.sort_ascending[idx];
                self.apply_sort();
                self.message = Some(format!(
                    "Sort: {} {}",
                    self.sort_field.label(),
                    if self.sort_asc() {
                        "\u{25b2}"
                    } else {
                        "\u{25bc}"
                    }
                ));
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
            Constraint::Min(5),    // table
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

        if self.mode == Mode::Search {
            frame.set_cursor_position((area.x + 1 + self.filter.len() as u16 + 1, area.y + 1));
        }
    }

    fn render_table(&mut self, frame: &mut Frame, area: Rect) {
        let sort = self.sort_field;
        let arrow = if self.sort_asc() {
            " \u{25b2}"
        } else {
            " \u{25bc}"
        };

        let header_label = |field: SortField, name: &str| -> Cell<'static> {
            if sort == field {
                Cell::from(format!("{name}{arrow}"))
                    .style(Style::default().bold().fg(Color::Yellow))
            } else {
                Cell::from(name.to_string()).style(Style::default().bold())
            }
        };

        // Available width inside the bordered block (subtract 2 for borders + 2 for highlight symbol)
        let inner_w = area.width.saturating_sub(4);

        // Columns dropped in order as terminal shrinks:
        //   Uses (5) → Created (12) → Changed (12) → Last Used (12)
        let show_uses = inner_w >= 80;
        let show_created = inner_w >= 120;
        let show_changed = inner_w >= 120;
        let show_last_used = inner_w >= 75;

        // Build columns dynamically
        let mut header_cells: Vec<Cell<'static>> = vec![
            header_label(SortField::Site, "Site"),
            header_label(SortField::Username, "Username"),
            Cell::from("Password").style(Style::default().bold()),
        ];
        let mut widths: Vec<Constraint> = vec![
            Constraint::Fill(3),
            Constraint::Fill(2),
            Constraint::Fill(1),
        ];

        if show_last_used {
            header_cells.push(header_label(SortField::LastUsed, "Last Used"));
            widths.push(Constraint::Length(12));
        }
        if show_created {
            header_cells.push(header_label(SortField::Created, "Created"));
            widths.push(Constraint::Length(12));
        }
        if show_changed {
            header_cells.push(header_label(SortField::Changed, "Changed"));
            widths.push(Constraint::Length(12));
        }
        if show_uses {
            header_cells.push(header_label(SortField::TimesUsed, "Uses"));
            widths.push(Constraint::Length(5));
        }

        let header = Row::new(header_cells).bottom_margin(1);

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
                let mut cells: Vec<Cell> = vec![
                    Cell::from(login.hostname.as_str()),
                    Cell::from(login.username.as_str()),
                    Cell::from(pw),
                ];
                if show_last_used {
                    cells.push(Cell::from(format_timestamp(login.time_last_used)));
                }
                if show_created {
                    cells.push(Cell::from(format_timestamp(login.time_created)));
                }
                if show_changed {
                    cells.push(Cell::from(format_timestamp(login.time_password_changed)));
                }
                if show_uses {
                    cells.push(Cell::from(login.times_used.to_string()));
                }
                Row::new(cells)
            })
            .collect();

        let count = format!(" {} logins ", self.filtered.len());
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
                Style::default().bg(Color::DarkGray).fg(Color::White)
            })
            .highlight_symbol("\u{25b8} ");

        frame.render_stateful_widget(table, area, &mut self.table_state);

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
                Span::styled("s", Style::default().fg(Color::Yellow)),
                Span::raw(" Sort  "),
                Span::styled("S", Style::default().fg(Color::Yellow)),
                Span::raw(" Reverse  "),
                Span::styled("q", Style::default().fg(Color::Yellow)),
                Span::raw(" Quit"),
            ])
        };

        let status = Paragraph::new(text).style(Style::default().bg(Color::Black));
        frame.render_widget(status, area);
    }
}

/// Format a millisecond timestamp as YYYY-MM-DD.
fn format_timestamp(ms: u64) -> String {
    if ms == 0 {
        return String::from("-");
    }
    let secs = (ms / 1000) as i64;
    // Days since Unix epoch
    let days = secs / 86400;
    // Civil date from days (algorithm from Howard Hinnant)
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}
