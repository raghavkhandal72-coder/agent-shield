use anyhow::Result;
use chrono::Utc;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, TableState, Wrap};
use ratatui::{Frame, Terminal};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::{Duration, Instant};

const MAX_EVENTS: usize = 2000;
const COST_PER_MILLION_TOKENS_USD: f64 = 3.0; // Blended Sonnet-class estimate

#[derive(Debug, Clone, Deserialize)]
struct AuditEvent {
    #[serde(default)]
    ts: String,
    #[serde(default = "default_server")]
    server: String,
    #[serde(default = "default_dash")]
    tool: String,
    #[serde(default)]
    direction: String,
    #[serde(default = "default_action")]
    action: String,
    #[serde(default)]
    detail: String,
    #[serde(default)]
    tokens_est: usize,
    #[serde(default)]
    payload: String,
}

fn default_server() -> String {
    "mcp".into()
}
fn default_dash() -> String {
    "-".into()
}
fn default_action() -> String {
    "INFO".into()
}

#[derive(Debug, Clone, Deserialize, Default)]
struct TaintFileSnapshot {
    #[serde(default)]
    private_sources: Vec<TaintMarkerView>,
    #[serde(default)]
    untrusted_sources: Vec<TaintMarkerView>,
    #[serde(default)]
    fingerprints: Vec<TaintFingerprintView>,
}

#[derive(Debug, Clone, Deserialize)]
struct TaintMarkerView {
    server: String,
    #[allow(dead_code)]
    tool: String,
    expires_at: i64,
}

#[derive(Debug, Clone, Deserialize)]
struct TaintFingerprintView {
    label: String,
    expires_at: i64,
}

#[derive(Debug, Default, Clone)]
struct ServerStats {
    requests: usize,
    blocked: usize,
    tokens: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum FilterMode {
    All,
    AlertsOnly,
    DlpAndTaint,
    RugPull,
}

impl FilterMode {
    fn next(self) -> Self {
        match self {
            FilterMode::All => FilterMode::AlertsOnly,
            FilterMode::AlertsOnly => FilterMode::DlpAndTaint,
            FilterMode::DlpAndTaint => FilterMode::RugPull,
            FilterMode::RugPull => FilterMode::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            FilterMode::All => "ALL",
            FilterMode::AlertsOnly => "ALERTS",
            FilterMode::DlpAndTaint => "DLP/TAINT",
            FilterMode::RugPull => "RUG-PULL",
        }
    }

    fn matches(self, ev: &AuditEvent) -> bool {
        let act = ev.action.to_ascii_uppercase();
        match self {
            FilterMode::All => true,
            FilterMode::AlertsOnly => act != "ALLOW" && act != "INFO",
            FilterMode::DlpAndTaint => {
                act.contains("DLP") || act.contains("TRIFECTA") || act.contains("TAINT")
            }
            FilterMode::RugPull => act.contains("RUG_PULL") || act.contains("MUTAT"),
        }
    }
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        execute!(io::stdout(), EnterAlternateScreen)?;
        Ok(Self)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
    }
}

struct AppState {
    audit_path: PathBuf,
    taint_path: PathBuf,
    file_offset: u64,
    events: Vec<AuditEvent>,
    table_state: TableState,
    filter: FilterMode,
    paused: bool,
    follow_tail: bool,
    inspector_scroll: u16,
    taint_snapshot: TaintFileSnapshot,
    server_stats: BTreeMap<String, ServerStats>,
    total_blocked: usize,
    total_tokens: usize,
    status_flash: Option<(String, Instant)>,
}

impl AppState {
    fn new(audit_path: PathBuf, taint_path: PathBuf) -> Self {
        Self {
            audit_path,
            taint_path,
            file_offset: 0,
            events: Vec::new(),
            table_state: TableState::default(),
            filter: FilterMode::All,
            paused: false,
            follow_tail: true,
            inspector_scroll: 0,
            taint_snapshot: TaintFileSnapshot::default(),
            server_stats: BTreeMap::new(),
            total_blocked: 0,
            total_tokens: 0,
            status_flash: None,
        }
    }

    fn poll_disk(&mut self) {
        self.poll_taint_state();
        if !self.paused {
            self.poll_audit_log();
        }
    }

    fn poll_taint_state(&mut self) {
        let Ok(raw) = fs::read_to_string(&self.taint_path) else {
            self.taint_snapshot = TaintFileSnapshot::default();
            return;
        };
        let now = Utc::now().timestamp();
        let mut snap: TaintFileSnapshot = serde_json::from_str(&raw).unwrap_or_default();
        snap.private_sources.retain(|m| m.expires_at > now);
        snap.untrusted_sources.retain(|m| m.expires_at > now);
        snap.fingerprints.retain(|f| f.expires_at > now);
        self.taint_snapshot = snap;
    }

    fn poll_audit_log(&mut self) {
        let Ok(meta) = fs::metadata(&self.audit_path) else {
            return;
        };

        // Handle log rotation or truncation
        if meta.len() < self.file_offset {
            self.file_offset = 0;
        }
        if meta.len() == self.file_offset {
            return;
        }

        let Ok(mut file) = File::open(&self.audit_path) else {
            return;
        };
        if file.seek(SeekFrom::Start(self.file_offset)).is_err() {
            return;
        }

        let mut reader = BufReader::new(file);
        let mut line = String::new();
        let mut added_any = false;

        loop {
            line.clear();
            let Ok(bytes) = reader.read_line(&mut line) else {
                break;
            };
            if bytes == 0 {
                break;
            }
            self.file_offset += bytes as u64;

            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(mut ev) = serde_json::from_str::<AuditEvent>(trimmed) {
                if ev.tokens_est == 0 {
                    ev.tokens_est = (ev.detail.len().max(ev.payload.len()) / 4).max(1);
                }
                self.record_stats(&ev);
                self.events.push(ev);
                added_any = true;
            }
        }

        if self.events.len() > MAX_EVENTS {
            let excess = self.events.len() - MAX_EVENTS;
            self.events.drain(0..excess);
        }

        if added_any && self.follow_tail {
            let visible = self.filtered_indices().len();
            if visible > 0 {
                self.table_state.select(Some(visible - 1));
                self.inspector_scroll = 0;
            }
        }
    }

    fn record_stats(&mut self, ev: &AuditEvent) {
        let entry = self.server_stats.entry(ev.server.clone()).or_default();
        entry.requests += 1;
        entry.tokens += ev.tokens_est;
        self.total_tokens += ev.tokens_est;

        let act = ev.action.to_ascii_uppercase();
        if act.contains("BLOCK") || act.contains("RUG_PULL") {
            entry.blocked += 1;
            self.total_blocked += 1;
        }
    }

    fn filtered_indices(&self) -> Vec<usize> {
        self.events
            .iter()
            .enumerate()
            .filter(|(_, e)| self.filter.matches(e))
            .map(|(i, _)| i)
            .collect()
    }

    fn selected_event(&self) -> Option<&AuditEvent> {
        let indices = self.filtered_indices();
        let sel = self.table_state.selected()?;
        let real_idx = *indices.get(sel)?;
        self.events.get(real_idx)
    }

    fn move_selection(&mut self, delta: isize) {
        let len = self.filtered_indices().len();
        if len == 0 {
            self.table_state.select(None);
            return;
        }
        let cur = self.table_state.selected().unwrap_or(len - 1) as isize;
        let next = (cur + delta).clamp(0, (len - 1) as isize) as usize;
        self.table_state.select(Some(next));
        self.follow_tail = next + 1 == len;
        self.inspector_scroll = 0;
    }

    fn clear_buffer(&mut self) {
        self.events.clear();
        self.server_stats.clear();
        self.total_blocked = 0;
        self.total_tokens = 0;
        self.table_state.select(None);
        self.inspector_scroll = 0;
        self.flash("Cleared in-memory view");
    }

    fn clear_taint_bus(&mut self) {
        if self.taint_path.exists() {
            let _ = fs::remove_file(&self.taint_path);
        }
        self.taint_snapshot = TaintFileSnapshot::default();
        self.flash("Wiped active taint state");
    }

    fn flash(&mut self, msg: &str) {
        self.status_flash = Some((msg.to_string(), Instant::now()));
    }
}

pub fn run_tui(audit_override: Option<PathBuf>) -> Result<()> {
    let base_dir = crate::policy::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".agent-shield");

    let audit_path = audit_override.unwrap_or_else(|| base_dir.join("audit.jsonl"));
    let taint_path = base_dir.join("taint_state.json");

    let _guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let mut app = AppState::new(audit_path, taint_path);
    app.poll_disk();

    let tick_rate = Duration::from_millis(150);

    loop {
        app.poll_disk();
        terminal.draw(|f| draw_ui(f, &mut app))?;

        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                // Crucial on Windows: ignore key-release duplicates
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Down | KeyCode::Char('j') => app.move_selection(1),
                    KeyCode::Up | KeyCode::Char('k') => app.move_selection(-1),
                    KeyCode::Char('g') | KeyCode::Home => {
                        app.follow_tail = false;
                        app.move_selection(-(MAX_EVENTS as isize));
                    }
                    KeyCode::Char('G') | KeyCode::End => {
                        app.follow_tail = true;
                        app.move_selection(MAX_EVENTS as isize);
                    }
                    KeyCode::PageDown | KeyCode::Char('J') => {
                        app.inspector_scroll = app.inspector_scroll.saturating_add(4);
                    }
                    KeyCode::PageUp | KeyCode::Char('K') => {
                        app.inspector_scroll = app.inspector_scroll.saturating_sub(4);
                    }
                    KeyCode::Char('f') => {
                        app.filter = app.filter.next();
                        let len = app.filtered_indices().len();
                        app.table_state
                            .select(if len > 0 { Some(len - 1) } else { None });
                        app.inspector_scroll = 0;
                    }
                    KeyCode::Char('p') | KeyCode::Char(' ') => {
                        app.paused = !app.paused;
                        app.flash(if app.paused {
                            "Stream PAUSED"
                        } else {
                            "Stream LIVE"
                        });
                    }
                    KeyCode::Char('c') => app.clear_buffer(),
                    KeyCode::Char('x') => app.clear_taint_bus(),
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

fn draw_ui(f: &mut Frame, app: &mut AppState) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),      // Top telemetry header
            Constraint::Percentage(58), // Live stream + right-side radar/tokens
            Constraint::Min(10),        // Burp-style payload/diff inspector
            Constraint::Length(1),      // Hotkey footer
        ])
        .split(f.area());

    draw_header(f, root[0], app);

    let middle = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(64), Constraint::Percentage(36)])
        .split(root[1]);

    draw_traffic_table(f, middle[0], app);

    let right_stack = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(7)])
        .split(middle[1]);

    draw_taint_radar(f, right_stack[0], app);
    draw_token_meter(f, right_stack[1], app);
    draw_inspector(f, root[2], app);
    draw_footer(f, root[3], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &AppState) {
    let est_cost = (app.total_tokens as f64 / 1_000_000.0) * COST_PER_MILLION_TOKENS_USD;
    let status_span = if app.paused {
        Span::styled(
            " PAUSED ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " LIVE ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    };

    let blocked_style = if app.total_blocked > 0 {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };

    let line = Line::from(vec![
        Span::styled(
            " AGENT-SHIELD ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        status_span,
        Span::raw("  Filter: "),
        Span::styled(
            app.filter.label(),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  |  Events: "),
        Span::styled(
            app.events.len().to_string(),
            Style::default().fg(Color::White),
        ),
        Span::raw("  |  Blocked: "),
        Span::styled(app.total_blocked.to_string(), blocked_style),
        Span::raw("  |  Tokens: "),
        Span::styled(
            format!("~{}", format_num(app.total_tokens)),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw(format!(" (${:.4})", est_cost)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" MCP Live Firewall & Inspector ");

    f.render_widget(Paragraph::new(line).block(block), area);
}

fn draw_traffic_table(f: &mut Frame, area: Rect, app: &mut AppState) {
    let indices = app.filtered_indices();
    let header = Row::new(["Time", "Server", "Dir", "Action", "Tool", "Tok", "Summary"])
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .bottom_margin(0);

    let rows: Vec<Row> = indices
        .iter()
        .map(|&idx| {
            let ev = &app.events[idx];
            let ts = short_time(&ev.ts);
            let dir = if ev.direction.starts_with("out") {
                "OUT"
            } else {
                "IN "
            };
            let badge_style = action_style(&ev.action);
            let summary: String = ev.detail.chars().take(48).collect();

            Row::new(vec![
                Cell::from(ts).style(Style::default().fg(Color::DarkGray)),
                Cell::from(ev.server.clone()).style(Style::default().fg(Color::White)),
                Cell::from(dir).style(Style::default().fg(Color::Gray)),
                Cell::from(ev.action.clone()).style(badge_style),
                Cell::from(ev.tool.clone()).style(Style::default().fg(Color::LightBlue)),
                Cell::from(ev.tokens_est.to_string()).style(Style::default().fg(Color::Yellow)),
                Cell::from(summary),
            ])
        })
        .collect();

    let widths = [
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Length(4),
        Constraint::Length(15),
        Constraint::Length(14),
        Constraint::Length(6),
        Constraint::Min(16),
    ];

    let title = format!(" Live MCP Traffic ({} shown) ", indices.len());
    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue))
                .title(title),
        )
        .row_highlight_style(
            Style::default()
                .bg(Color::Rgb(35, 45, 65))
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("> ");

    f.render_stateful_widget(table, area, &mut app.table_state);
}

fn draw_taint_radar(f: &mut Frame, area: Rect, app: &AppState) {
    let priv_set: BTreeSet<String> = app
        .taint_snapshot
        .private_sources
        .iter()
        .map(|m| m.server.clone())
        .collect();
    let untrusted_set: BTreeSet<String> = app
        .taint_snapshot
        .untrusted_sources
        .iter()
        .map(|m| m.server.clone())
        .collect();

    let trifecta_armed = !priv_set.is_empty() && !untrusted_set.is_empty();
    let anchors = app.taint_snapshot.fingerprints.len();

    let mut label_counts: BTreeMap<&str, usize> = BTreeMap::new();
    for fp in &app.taint_snapshot.fingerprints {
        *label_counts.entry(fp.label.as_str()).or_default() += 1;
    }
    let top_labels: String = label_counts
        .into_iter()
        .take(3)
        .map(|(k, v)| format!("{}({})", k, v))
        .collect::<Vec<_>>()
        .join(", ");

    let state_line = if trifecta_armed {
        Line::from(vec![
            Span::raw("Status   : "),
            Span::styled(
                " LETHAL TRIFECTA ARMED ",
                Style::default()
                    .fg(Color::White)
                    .bg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    } else if anchors > 0 {
        Line::from(vec![
            Span::raw("Status   : "),
            Span::styled(
                " TAINTED (DLP WATCHING) ",
                Style::default().fg(Color::Black).bg(Color::Yellow),
            ),
        ])
    } else {
        Line::from(vec![
            Span::raw("Status   : "),
            Span::styled(
                " CLEAN ",
                Style::default().fg(Color::Black).bg(Color::Green),
            ),
        ])
    };

    let priv_text = if priv_set.is_empty() {
        "none".into()
    } else {
        priv_set.into_iter().collect::<Vec<_>>().join(", ")
    };
    let untrusted_text = if untrusted_set.is_empty() {
        "none".into()
    } else {
        untrusted_set.into_iter().collect::<Vec<_>>().join(", ")
    };

    let lines = vec![
        state_line,
        Line::from(vec![
            Span::styled("Private  : ", Style::default().fg(Color::Gray)),
            Span::styled(priv_text, Style::default().fg(Color::Yellow)),
        ]),
        Line::from(vec![
            Span::styled("Untrusted: ", Style::default().fg(Color::Gray)),
            Span::styled(untrusted_text, Style::default().fg(Color::LightRed)),
        ]),
        Line::from(vec![
            Span::styled("Anchors  : ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{} SHA-256 hashes", anchors),
                Style::default().fg(Color::Cyan),
            ),
        ]),
        Line::from(vec![
            Span::styled("Types    : ", Style::default().fg(Color::Gray)),
            Span::raw(if top_labels.is_empty() {
                "-"
            } else {
                &top_labels
            }),
        ]),
    ];

    let border_color = if trifecta_armed {
        Color::Red
    } else {
        Color::DarkGray
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_color))
        .title(" Cross-Server Taint Radar ");

    f.render_widget(
        Paragraph::new(lines).block(block).wrap(Wrap { trim: true }),
        area,
    );
}

fn draw_token_meter(f: &mut Frame, area: Rect, app: &AppState) {
    let mut ranked: Vec<(&String, &ServerStats)> = app.server_stats.iter().collect();
    ranked.sort_by_key(|a| std::cmp::Reverse(a.1.tokens));

    let max_tok = ranked.first().map(|(_, s)| s.tokens).unwrap_or(1).max(1);

    let header = Row::new(["Server", "Reqs", "Blk", "Tokens", "Burn"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let rows: Vec<Row> = ranked
        .into_iter()
        .map(|(srv, st)| {
            let filled = ((st.tokens * 8) / max_tok).clamp(1, 8);
            let bar = format!("{}{}", "#".repeat(filled), ".".repeat(8 - filled));
            let blk_style = if st.blocked > 0 {
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            Row::new(vec![
                Cell::from(srv.clone()),
                Cell::from(st.requests.to_string()),
                Cell::from(st.blocked.to_string()).style(blk_style),
                Cell::from(format_num(st.tokens)).style(Style::default().fg(Color::Yellow)),
                Cell::from(bar).style(Style::default().fg(Color::Cyan)),
            ])
        })
        .collect();

    let widths = [
        Constraint::Min(10),
        Constraint::Length(5),
        Constraint::Length(4),
        Constraint::Length(7),
        Constraint::Length(9),
    ];

    let table = Table::new(rows, widths).header(header).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray))
            .title(" Per-Server Token Burn "),
    );

    f.render_widget(table, area);
}

fn draw_inspector(f: &mut Frame, area: Rect, app: &AppState) {
    let mut lines: Vec<Line> = Vec::new();

    if let Some(ev) = app.selected_event() {
        lines.push(Line::from(vec![
            Span::styled("Action: ", Style::default().fg(Color::Gray)),
            Span::styled(ev.action.clone(), action_style(&ev.action)),
            Span::raw("   "),
            Span::styled("Target: ", Style::default().fg(Color::Gray)),
            Span::styled(
                format!("{}::{}", ev.server, ev.tool),
                Style::default().fg(Color::LightBlue),
            ),
            Span::raw("   "),
            Span::styled("Timestamp: ", Style::default().fg(Color::Gray)),
            Span::raw(ev.ts.clone()),
        ]));

        lines.push(Line::from(vec![
            Span::styled("Reason: ", Style::default().fg(Color::Gray)),
            Span::styled(ev.detail.clone(), Style::default().fg(Color::White)),
        ]));

        if !ev.payload.is_empty() {
            lines.push(Line::from(Span::styled(
                "--- Payload / Diff ---",
                Style::default().fg(Color::DarkGray),
            )));

            let formatted = serde_json::from_str::<serde_json::Value>(&ev.payload)
                .ok()
                .and_then(|v| serde_json::to_string_pretty(&v).ok())
                .unwrap_or_else(|| ev.payload.clone());

            for l in formatted.lines() {
                let style = if l.trim_start().starts_with('-') {
                    Style::default().fg(Color::Red)
                } else if l.trim_start().starts_with('+') {
                    Style::default().fg(Color::Green)
                } else {
                    Style::default().fg(Color::Gray)
                };
                lines.push(Line::from(Span::styled(l.to_string(), style)));
            }
        }
    } else {
        lines.push(Line::from(Span::styled(
            format!("Waiting for MCP events in {} ...", app.audit_path.display()),
            Style::default().fg(Color::DarkGray),
        )));
        lines.push(Line::from(Span::styled(
            "Tip: Run `agent-shield wrap ...` or `cargo test` in another pane to see live blocks.",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray))
        .title(" Payload & Diff Inspector (J/K or PgUp/PgDn to scroll) ");

    let para = Paragraph::new(lines)
        .block(block)
        .wrap(Wrap { trim: false })
        .scroll((app.inspector_scroll, 0));

    f.render_widget(para, area);
}

fn draw_footer(f: &mut Frame, area: Rect, app: &AppState) {
    let mut text = String::from(
        " [j/k] Navigate | [J/K] Scroll Payload | [f] Filter | [p] Pause | [c] Clear View | [x] Wipe Taint | [q] Quit",
    );

    if let Some((msg, when)) = &app.status_flash {
        if when.elapsed() < Duration::from_secs(3) {
            text = format!(" >> {}   |  {}", msg, text);
        }
    }

    f.render_widget(
        Paragraph::new(text).style(Style::default().fg(Color::Black).bg(Color::Cyan)),
        area,
    );
}

fn action_style(action: &str) -> Style {
    let act = action.to_ascii_uppercase();
    if act.contains("RUG_PULL") || act.contains("DLP") || act.contains("TRIFECTA_BLOCK") {
        Style::default()
            .fg(Color::White)
            .bg(Color::Red)
            .add_modifier(Modifier::BOLD)
    } else if act.contains("BLOCK") {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else if act.contains("SANITIZ") || act.contains("WARN") || act.contains("AUDIT") {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else if act == "ALLOW" {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Gray)
    }
}

fn short_time(iso: &str) -> String {
    if let Some(t_pos) = iso.find('T') {
        let rest = &iso[t_pos + 1..];
        if rest.len() >= 8 {
            return rest[..8].to_string();
        }
    }
    iso.chars().take(8).collect()
}

fn format_num(n: usize) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}k", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}
