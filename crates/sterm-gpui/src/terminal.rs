use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::num::NonZeroU16;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};

use gpui::{
    canvas, div, font, prelude::*, px, Bounds, FontWeight, HighlightStyle, Keystroke, Pixels,
    Point, SharedString, StyledText, TextRun, UnderlineStyle,
};

use tokio::sync::mpsc;

use crate::backend::UiEvent;
use crate::theme::{vt_color_to_hsla, TerminalCursorStyle, TerminalThemeId, ThemePalette};

pub const DEFAULT_TERM_COLS: u16 = 112;
pub const DEFAULT_TERM_ROWS: u16 = 34;
const TERM_SCROLLBACK_LEN: usize = 2000;

#[cfg(test)]
pub fn terminal_line_height(font_size: f32) -> f32 {
    terminal_line_height_scaled(font_size, 1.42)
}

pub fn terminal_line_height_scaled(font_size: f32, mult: f32) -> f32 {
    (font_size * mult.clamp(1.1, 1.8)).round().max(10.0)
}

/// A buffer-anchored position inside the terminal history or active screen.
///
/// `col` is a character-boundary column in `0..=cols`, so selections span the half-open
/// column interval `[start.col, end.col)` (on a single row) or from `start.col..cols`
/// through `0..end.col` across multiple rows — matching PowerShell / Windows Terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct TerminalPos {
    /// Absolute logical row index:
    /// - Normal screen: `discarded_rows + scrollback_len - scrollback_offset + visible_row`
    /// - Alternate screen: `visible_row as usize`
    pub abs_row: usize,
    /// Boundary column in `0..=cols`.
    pub col: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSelection {
    pub start: TerminalPos,
    pub end: TerminalPos,
    pub is_alt: bool,
}

impl TerminalSelection {
    pub fn ordered(&self) -> (TerminalPos, TerminalPos) {
        if self.start <= self.end {
            (self.start, self.end)
        } else {
            (self.end, self.start)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.start == self.end
    }

    /// Returns whether the cell at `(abs_row, col)` on screen mode `is_alt` is highlighted.
    pub fn contains(&self, is_alt: bool, abs_row: usize, col: u16) -> bool {
        if self.is_alt != is_alt || self.is_empty() {
            return false;
        }
        let (start, end) = self.ordered();
        if abs_row < start.abs_row || abs_row > end.abs_row {
            return false;
        }
        if start.abs_row == end.abs_row {
            col >= start.col && col < end.col
        } else if abs_row == start.abs_row {
            col >= start.col
        } else if abs_row == end.abs_row {
            col < end.col
        } else {
            true
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TerminalSelectionMode {
    #[default]
    Char,
    Word {
        anchor_start: TerminalPos,
        anchor_end: TerminalPos,
    },
    Line {
        anchor_start_row: usize,
        anchor_end_row: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CellCharClass {
    Space,
    Delimiter,
    Word,
}

fn cell_char_class(cell: Option<&vt100::Cell>) -> CellCharClass {
    let Some(cell) = cell else {
        return CellCharClass::Space;
    };
    let s = cell.contents();
    if s.is_empty() || s.chars().all(|ch| ch.is_whitespace()) {
        return CellCharClass::Space;
    }
    if s.chars().all(|ch| {
        matches!(
            ch,
            '(' | ')' | '[' | ']' | '{' | '}' | '<' | '>' | '"' | '\'' | '`' | ',' | ';' | '|'
        )
    }) {
        return CellCharClass::Delimiter;
    }
    CellCharClass::Word
}

/// A detected clickable link (either a single/multi-line wrapped URL or an OSC 8 hyperlink).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoveredUrl {
    /// Covered `(row, start_col, end_col)` inclusive segments across one or more rows.
    pub spans: Vec<(u16, u16, u16)>,
    pub url: String,
}

impl HoveredUrl {
    pub fn contains(&self, row: u16, col: u16) -> bool {
        self.spans
            .iter()
            .any(|&(r, sc, ec)| r == row && col >= sc && col <= ec)
    }
}

#[derive(Debug, Clone)]
struct Osc8LinkEntry {
    is_alt: bool,
    /// Absolute row indices (`scrollback_len + discarded_rows + row` in normal screen,
    /// or `row` in alternate screen), with inclusive `(start_col, end_col)`.
    abs_spans: Vec<(usize, u16, u16)>,
    url: String,
    /// Sampled first non-space character of the link so cleared/overwritten cells don't false-match.
    anchor_char: Option<(usize, u16, char)>,
}

/// Tracks OSC 8 terminal hyperlinks (`\x1b]8;;https://...\x07Click here\x1b]8;;\x07`).
#[derive(Debug, Default)]
pub struct Osc8Tracker {
    active: Option<(bool, usize, u16, String)>,
    links: Vec<Osc8LinkEntry>,
    discarded_rows: usize,
}

impl Osc8Tracker {
    pub fn discarded_rows(&self) -> usize {
        self.discarded_rows
    }

    fn abs_row(&self, screen: &vt100::Screen, row: u16) -> usize {
        if screen.alternate_screen() {
            row as usize
        } else {
            screen
                .scrollback_len()
                .saturating_add(self.discarded_rows)
                .saturating_add(row as usize)
        }
    }

    pub fn visible_base_abs_row(&self, screen: &vt100::Screen) -> usize {
        if screen.alternate_screen() {
            0
        } else {
            screen
                .scrollback_len()
                .saturating_add(self.discarded_rows)
                .saturating_sub(screen.scrollback())
        }
    }

    pub fn find_at(&self, screen: &vt100::Screen, row: u16, col: u16) -> Option<HoveredUrl> {
        let is_alt = screen.alternate_screen();
        let (rows_nz, _) = screen.size();
        let rows = rows_nz.get() as usize;
        let base = self.visible_base_abs_row(screen);
        let target_abs = base.saturating_add(row as usize);

        for entry in self.links.iter().rev() {
            if entry.is_alt != is_alt {
                continue;
            }
            if !entry
                .abs_spans
                .iter()
                .any(|&(r, sc, ec)| r == target_abs && col >= sc && col <= ec)
            {
                continue;
            }

            // Verify screen wasn't cleared/overwritten over the anchor cell
            if let Some((ar, ac, expected_ch)) = entry.anchor_char
                && ar >= base && ar < base + rows {
                    let vis_r = (ar - base) as u16;
                    let actual_ch = screen
                        .cell(vis_r, ac)
                        .and_then(|c| c.contents().chars().next())
                        .unwrap_or(' ');
                    if actual_ch != expected_ch {
                        continue;
                    }
                }

            let spans: Vec<(u16, u16, u16)> = entry
                .abs_spans
                .iter()
                .filter_map(|&(abs_r, sc, ec)| {
                    if abs_r >= base && abs_r < base + rows {
                        Some(((abs_r - base) as u16, sc, ec))
                    } else {
                        None
                    }
                })
                .collect();

            if !spans.is_empty() {
                return Some(HoveredUrl {
                    spans,
                    url: entry.url.clone(),
                });
            }
        }
        None
    }
}

impl vt100::Callbacks for Osc8Tracker {
    fn unhandled_osc(&mut self, screen: &mut vt100::Screen, params: &[&[u8]]) {
        if params.first().copied() != Some(b"8") || params.len() < 3 {
            return;
        }
        let uri = params[2..]
            .iter()
            .map(|p| String::from_utf8_lossy(p))
            .collect::<Vec<_>>()
            .join(";")
            .trim()
            .to_string();
        let is_alt = screen.alternate_screen();
        let (cur_row, cur_col) = screen.cursor_position();
        let cur_abs_row = self.abs_row(screen, cur_row);
        let (rows_nz, cols_nz) = screen.size();
        let max_col = cols_nz.get().saturating_sub(1);

        if uri.is_empty() {
            if let Some((start_alt, sr, sc, url)) = self.active.take() {
                if start_alt != is_alt {
                    return;
                }
                let mut abs_spans = Vec::new();
                if cur_abs_row == sr {
                    if cur_col > sc {
                        abs_spans.push((sr, sc, (cur_col - 1).min(max_col)));
                    }
                } else if cur_abs_row > sr {
                    abs_spans.push((sr, sc, max_col));
                    for r in (sr + 1)..cur_abs_row {
                        abs_spans.push((r, 0, max_col));
                    }
                    if cur_col > 0 {
                        abs_spans.push((cur_abs_row, 0, (cur_col - 1).min(max_col)));
                    }
                }
                if !abs_spans.is_empty() {
                    let base = self.abs_row(screen, 0);
                    let rows = rows_nz.get() as usize;
                    let mut anchor_char = None;
                    'find_anchor: for &(ar, s_col, e_col) in &abs_spans {
                        if ar >= base && ar < base + rows {
                            let vis_r = (ar - base) as u16;
                            for c in s_col..=e_col {
                                if let Some(ch) = screen
                                    .cell(vis_r, c)
                                    .and_then(|cell| cell.contents().chars().next())
                                    && !ch.is_whitespace() {
                                        anchor_char = Some((ar, c, ch));
                                        break 'find_anchor;
                                    }
                            }
                        }
                    }

                    self.links.retain(|l| {
                        l.is_alt != is_alt
                            || !l.abs_spans.iter().any(|(r, sc0, ec0)| {
                                abs_spans.iter().any(|(nr, sc1, ec1)| {
                                    nr == r && sc0 <= ec1 && sc1 <= ec0
                                })
                            })
                    });
                    self.links.push(Osc8LinkEntry {
                        is_alt,
                        abs_spans,
                        url,
                        anchor_char,
                    });
                    if self.links.len() > 128 {
                        self.links.remove(0);
                    }
                }
            }
        } else if uri.starts_with("http://") || uri.starts_with("https://") {
            self.active = Some((is_alt, cur_abs_row, cur_col, uri));
        }
    }

    fn on_scroll(&mut self, _contents: vt100::capture::RowContents<'_>, alternate_screen: bool) {
        if !alternate_screen {
            self.discarded_rows = self.discarded_rows.saturating_add(1);
        }
    }
}

/// A live SSH terminal session backed by `vt100::Parser` with mouse selection, scrollback,
/// multi-line wrapped URLs, and OSC 8 hyperlinks.
#[allow(dead_code)]
pub struct TerminalTab {
    pub tab_id: String,
    pub session_id: Option<String>,
    pub host_id: Option<String>,
    pub label: String,
    pub hostname: String,
    pub port: u16,
    pub username: String,
    pub theme_id: Option<String>,
    pub connected: bool,
    pub is_auth_error: bool,
    pub last_error: Option<String>,
    pub status_line: String,
    pub parser: vt100::Parser<Osc8Tracker>,
    pub cols: u16,
    pub rows: u16,
    pub line_height_mult: f32,
    pub selection: Option<TerminalSelection>,
    pub selection_mode: TerminalSelectionMode,
    pub is_selecting: bool,
    pub drag_mouse_pos: Option<Point<Pixels>>,
    pub drag_scroll_active: bool,
    pub hovered_url: Option<HoveredUrl>,
    pub screen_bounds: Arc<Mutex<Option<Bounds<Pixels>>>>,
    pub cell_width: Arc<Mutex<f32>>,
    pub last_requested_size: Arc<Mutex<(u16, u16)>>,
    pub pty_resize_seq: Arc<AtomicU64>,
    pub last_pty_size: Arc<Mutex<(u16, u16)>>,
    // Live command tracking for inline suggestions
    pub typed_line: String,
    pub recent_output_tail: String,
    // In-terminal search state (Ctrl/Cmd+F)
    pub search_query: String,
    pub search_matches: Vec<(usize, u16, u16)>,
    pub active_match_idx: usize,
    // Phase 3: Local PTY shell, environment stripe, auto-reconnect & transcript logging
    pub is_local: bool,
    pub env_label: Option<&'static str>,
    pub manually_closed: bool,
    pub reconnect_attempts: u32,
    pub transcript_path: Option<PathBuf>,
    pub transcript_file: Option<File>,
}

impl TerminalTab {
    pub fn connecting(
        tab_id: String,
        host_id: Option<String>,
        label: String,
        hostname: String,
        port: u16,
        username: String,
    ) -> Self {
        let mut parser = vt100::Parser::new_with_callbacks(
            NonZeroU16::new(DEFAULT_TERM_ROWS).unwrap(),
            NonZeroU16::new(DEFAULT_TERM_COLS).unwrap(),
            TERM_SCROLLBACK_LEN,
            Osc8Tracker::default(),
        );
        let banner = format!(
            "\x1b[38;5;75mSTerm SSH\x1b[0m · Connecting to \x1b[1m{}@{}:{}\x1b[0m...\r\n",
            username, hostname, port
        );
        parser.process(banner.as_bytes());
        Self {
            tab_id,
            session_id: None,
            host_id,
            label,
            hostname,
            port,
            username,
            theme_id: None,
            connected: false,
            is_auth_error: false,
            last_error: None,
            status_line: "Connecting...".to_string(),
            parser,
            cols: DEFAULT_TERM_COLS,
            rows: DEFAULT_TERM_ROWS,
            line_height_mult: 1.42,
            selection: None,
            selection_mode: TerminalSelectionMode::Char,
            is_selecting: false,
            drag_mouse_pos: None,
            drag_scroll_active: false,
            hovered_url: None,
            screen_bounds: Arc::new(Mutex::new(None)),
            cell_width: Arc::new(Mutex::new(7.8)),
            last_requested_size: Arc::new(Mutex::new((DEFAULT_TERM_COLS, DEFAULT_TERM_ROWS))),
            pty_resize_seq: Arc::new(AtomicU64::new(0)),
            last_pty_size: Arc::new(Mutex::new((DEFAULT_TERM_COLS, DEFAULT_TERM_ROWS))),
            typed_line: String::new(),
            recent_output_tail: String::new(),
            search_query: String::new(),
            search_matches: Vec::new(),
            active_match_idx: 0,
            is_local: false,
            env_label: None,
            manually_closed: false,
            reconnect_attempts: 0,
            transcript_path: None,
            transcript_file: None,
        }
    }

    pub fn local_shell(tab_id: String, label: String, session_id: String, program: String) -> Self {
        let parser = vt100::Parser::new_with_callbacks(
            NonZeroU16::new(DEFAULT_TERM_ROWS).unwrap(),
            NonZeroU16::new(DEFAULT_TERM_COLS).unwrap(),
            TERM_SCROLLBACK_LEN,
            Osc8Tracker::default(),
        );
        Self {
            tab_id,
            session_id: Some(session_id),
            host_id: None,
            label,
            hostname: program,
            port: 0,
            username: "local".into(),
            theme_id: None,
            connected: true,
            is_auth_error: false,
            last_error: None,
            status_line: "Live · Local PTY".to_string(),
            parser,
            cols: DEFAULT_TERM_COLS,
            rows: DEFAULT_TERM_ROWS,
            line_height_mult: 1.42,
            selection: None,
            selection_mode: TerminalSelectionMode::Char,
            is_selecting: false,
            drag_mouse_pos: None,
            drag_scroll_active: false,
            hovered_url: None,
            screen_bounds: Arc::new(Mutex::new(None)),
            cell_width: Arc::new(Mutex::new(7.8)),
            last_requested_size: Arc::new(Mutex::new((DEFAULT_TERM_COLS, DEFAULT_TERM_ROWS))),
            pty_resize_seq: Arc::new(AtomicU64::new(0)),
            last_pty_size: Arc::new(Mutex::new((DEFAULT_TERM_COLS, DEFAULT_TERM_ROWS))),
            typed_line: String::new(),
            recent_output_tail: String::new(),
            search_query: String::new(),
            search_matches: Vec::new(),
            active_match_idx: 0,
            is_local: true,
            env_label: Some("LOCAL"),
            manually_closed: false,
            reconnect_attempts: 0,
            transcript_path: None,
            transcript_file: None,
        }
    }

    pub fn start_transcript(&mut self, path: PathBuf) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("failed to open transcript file: {e}"))?;
        let header = format!(
            "\n--- STerm Session Log started {} ({}) ---\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
            self.label
        );
        let _ = file.write_all(header.as_bytes());
        let _ = file.flush();
        self.transcript_path = Some(path);
        self.transcript_file = Some(file);
        Ok(())
    }

    pub fn stop_transcript(&mut self) {
        if let Some(mut f) = self.transcript_file.take() {
            let footer = format!(
                "\n--- STerm Session Log ended {} ---\n",
                chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
            );
            let _ = f.write_all(footer.as_bytes());
            let _ = f.flush();
        }
        self.transcript_path = None;
    }

    pub fn is_alternate_screen(&self) -> bool {
        self.parser.screen().alternate_screen()
    }

    pub fn clear_buffer(&mut self) {
        self.parser = vt100::Parser::new_with_callbacks(
            NonZeroU16::new(self.rows.max(4)).unwrap(),
            NonZeroU16::new(self.cols.max(20)).unwrap(),
            TERM_SCROLLBACK_LEN,
            Osc8Tracker::default(),
        );
        self.clear_selection();
        self.hovered_url = None;
        self.search_matches.clear();
        self.active_match_idx = 0;
        self.recent_output_tail.clear();
        self.typed_line.clear();
    }

    pub fn cursor_in_bottom_half(&self) -> bool {
        let (cur_row, _) = self.parser.screen().cursor_position();
        cur_row as usize >= (self.rows as usize / 2)
    }

    pub fn scroll_to_abs_row(&mut self, abs_row: usize) {
        let screen = self.parser.screen();
        if screen.alternate_screen() {
            return;
        }
        let rows = self.rows as usize;
        let vis_base = self.visible_base_abs_row();
        if abs_row >= vis_base && abs_row < vis_base + rows {
            return;
        }
        let min_abs = self.min_abs_row();
        let live_top_abs = min_abs.saturating_add(screen.scrollback_len());
        let desired_top = abs_row.saturating_sub(rows / 3);
        let offset = live_top_abs.saturating_sub(desired_top);
        self.parser.screen_mut().set_scrollback(offset);
    }

    pub fn update_search(&mut self, query: &str) {
        self.search_query = query.to_string();
        self.search_matches.clear();
        self.active_match_idx = 0;

        let needle = query.trim().to_lowercase();
        if needle.is_empty() {
            return;
        }

        let is_alt = self.parser.screen().alternate_screen();
        let (rows_nz, cols_nz) = self.parser.screen().size();
        let rows = rows_nz.get() as usize;
        let cols = cols_nz.get();
        let min_abs = self.min_abs_row();
        let max_abs_excl = self.max_abs_row_excl();
        if max_abs_excl <= min_abs {
            return;
        }

        let saved_offset = self.parser.screen().scrollback();
        let live_top_abs = if is_alt {
            0
        } else {
            min_abs.saturating_add(self.parser.screen().scrollback_len())
        };

        let mut cur = min_abs;
        while cur < max_abs_excl {
            let vis_base = self.visible_base_abs_row();
            if !(cur >= vis_base && cur < vis_base + rows) {
                let target_offset = live_top_abs.saturating_sub(cur);
                self.parser.screen_mut().set_scrollback(target_offset);
            }
            let vis_base = self.visible_base_abs_row();
            let window_end = (vis_base + rows).min(max_abs_excl);
            let screen = self.parser.screen();

            for abs_r in cur..window_end {
                let vis_r = (abs_r - vis_base) as u16;
                let mut line = String::with_capacity(cols as usize);
                let mut col_for_byte: Vec<u16> = Vec::with_capacity(cols as usize);
                for c in 0..cols {
                    if let Some(cell) = screen.cell(vis_r, c) {
                        if cell.is_wide_continuation() {
                            continue;
                        }
                        let s = if cell.has_contents() {
                            cell.contents()
                        } else {
                            " "
                        };
                        let lower = s.to_lowercase();
                        for _ in lower.bytes() {
                            col_for_byte.push(c);
                        }
                        line.push_str(&lower);
                    } else {
                        col_for_byte.push(c);
                        line.push(' ');
                    }
                }
                let mut offset = 0;
                while let Some(pos) = line[offset..].find(&needle) {
                    let start_b = offset + pos;
                    let end_b = start_b + needle.len();
                    if let (Some(&sc), Some(&ec)) = (
                        col_for_byte.get(start_b),
                        col_for_byte.get(end_b.saturating_sub(1)),
                    ) {
                        self.search_matches.push((abs_r, sc, ec + 1));
                    }
                    offset = start_b + needle.len().max(1);
                    if offset >= line.len() {
                        break;
                    }
                }
            }
            cur = window_end;
        }

        if self.parser.screen().scrollback() != saved_offset {
            self.parser.screen_mut().set_scrollback(saved_offset);
        }

        // Jump to most recent match (closest to bottom) first
        if !self.search_matches.is_empty() {
            self.active_match_idx = self.search_matches.len() - 1;
            let abs_r = self.search_matches[self.active_match_idx].0;
            self.scroll_to_abs_row(abs_r);
        }
    }

    pub fn next_search_match(&mut self) {
        if self.search_matches.is_empty() {
            return;
        }
        self.active_match_idx = (self.active_match_idx + 1) % self.search_matches.len();
        let abs_r = self.search_matches[self.active_match_idx].0;
        self.scroll_to_abs_row(abs_r);
    }

    pub fn prev_search_match(&mut self) {
        if self.search_matches.is_empty() {
            return;
        }
        self.active_match_idx =
            (self.active_match_idx + self.search_matches.len() - 1) % self.search_matches.len();
        let abs_r = self.search_matches[self.active_match_idx].0;
        self.scroll_to_abs_row(abs_r);
    }

    pub fn feed_bytes(&mut self, bytes: &[u8]) {
        let was_alt = self.parser.screen().alternate_screen();
        let old_live_top_abs = if was_alt {
            0
        } else {
            self.parser
                .callbacks()
                .discarded_rows()
                .saturating_add(self.parser.screen().scrollback_len())
        };

        self.parser.process(bytes);

        // Append clean ANSI-stripped output to active session transcript log if recording
        if !bytes.is_empty()
            && let Some(ref mut log_file) = self.transcript_file
        {
            let clean = strip_ansi_for_log(bytes);
            if !clean.is_empty() {
                let _ = log_file.write_all(clean.as_bytes());
                let _ = log_file.flush();
            }
        }

        // Keep last ~240 chars of UTF-8 output for password-prompt detection in command recording
        if !bytes.is_empty() {
            let chunk = String::from_utf8_lossy(bytes);
            self.recent_output_tail.push_str(&chunk);
            if self.recent_output_tail.len() > 480 {
                let mut cut = self.recent_output_tail.len() - 240;
                while !self.recent_output_tail.is_char_boundary(cut) {
                    cut += 1;
                }
                self.recent_output_tail.drain(..cut);
            }
        }

        let now_alt = self.parser.screen().alternate_screen();
        let new_live_top_abs = if now_alt {
            0
        } else {
            self.parser
                .callbacks()
                .discarded_rows()
                .saturating_add(self.parser.screen().scrollback_len())
        };

        // Screen mode switch (e.g. entering/leaving vim/htop) or full RIS terminal reset (\x1bc)
        let saw_ris = bytes.windows(2).any(|w| w == b"\x1bc");
        if was_alt != now_alt || saw_ris || (!now_alt && new_live_top_abs < old_live_top_abs) {
            self.clear_selection();
        } else {
            self.clamp_or_clear_selection();
        }
    }

    pub fn append_system_line(&mut self, line: &str) {
        let formatted = format!("\r\n\x1b[38;5;214m[sterm]\x1b[0m {line}\r\n");
        self.feed_bytes(formatted.as_bytes());
    }

    pub fn resize(&mut self, cols: u16, rows: u16) -> bool {
        let cols = cols.clamp(20, 400);
        let rows = rows.clamp(4, 200);
        if let Ok(mut last) = self.last_requested_size.lock() {
            *last = (cols, rows);
        }
        if cols != self.cols || rows != self.rows {
            let width_changed = cols != self.cols;
            self.cols = cols;
            self.rows = rows;
            self.clear_selection();
            self.hovered_url = None;

            if width_changed && !self.parser.screen().alternate_screen() {
                self.reflow_parser(cols, rows);
            } else {
                self.parser.set_size(
                    NonZeroU16::new(rows).unwrap(),
                    NonZeroU16::new(cols).unwrap(),
                );
            }
            true
        } else {
            false
        }
    }

    /// Re-wraps normal-screen scrollback and visible lines to `(cols, rows)` instead of
    /// letting `vt100::Grid::set_size` truncate columns beyond `cols` when narrowing.
    fn reflow_parser(&mut self, cols: u16, rows: u16) {
        self.parser.screen_mut().set_scrollback(0);
        let screen = self.parser.screen();
        let (old_rows_nz, old_cols_nz) = screen.size();
        let old_rows = old_rows_nz.get();
        let old_cols = old_cols_nz.get();
        let (cur_row, cur_col) = screen.cursor_position();

        let is_non_default_cell = |cell: &vt100::Cell| -> bool {
            cell.has_contents()
                || cell.bgcolor() != vt100::Color::Default
                || cell.fgcolor() != vt100::Color::Default
                || cell.bold()
                || cell.underline()
                || cell.inverse()
                || cell.italic()
        };

        let mut last_non_empty_row: Option<u16> = None;
        for r in (0..old_rows).rev() {
            if (0..old_cols).any(|c| screen.cell(r, c).is_some_and(is_non_default_cell)) {
                last_non_empty_row = Some(r);
                break;
            }
        }
        let keep_until_row = cur_row.max(last_non_empty_row.unwrap_or(0));
        let trailing_blank_rows = (old_rows.saturating_sub(1)).saturating_sub(keep_until_row) as usize;

        let cur_row_content_len = (0..old_cols)
            .rev()
            .find(|&c| screen.cell(cur_row, c).is_some_and(is_non_default_cell))
            .map(|c| c + 1)
            .unwrap_or(0);

        let mut logical_start_row = cur_row;
        while logical_start_row > 0 && screen.row_wrapped(logical_start_row - 1) {
            logical_start_row -= 1;
        }
        let logical_cur_col =
            (cur_row - logical_start_row) as usize * old_cols as usize + cur_col as usize;

        let input_modes = screen.input_mode_formatted();
        let attrs = screen.attributes_formatted();
        let hide_cursor = screen.hide_cursor();

        let mut full = String::new();
        let mut capture_state = vt100::capture::BasicFormattedCaptureState::new();
        let _ = screen.write_contents_formatted_basic(
            &mut full,
            vt100::capture::BasicFormattedCaptureRange::Full(&mut capture_state),
        );
        for _ in 0..trailing_blank_rows {
            if full.ends_with('\n') {
                full.pop();
            } else {
                break;
            }
        }

        let mut replay = String::with_capacity(full.len() + full.len() / 16 + 16);
        for ch in full.chars() {
            if ch == '\n' {
                replay.push_str("\r\n");
            } else {
                replay.push(ch);
            }
        }

        let mut new_parser = vt100::Parser::new_with_callbacks(
            NonZeroU16::new(rows).unwrap(),
            NonZeroU16::new(cols).unwrap(),
            TERM_SCROLLBACK_LEN,
            Osc8Tracker::default(),
        );
        if !replay.is_empty() {
            new_parser.process(replay.as_bytes());
            new_parser.process(b"\x1b[0m");
        }

        if cur_row < keep_until_row {
            let rows_below = keep_until_row - cur_row;
            let (end_row, _) = new_parser.screen().cursor_position();
            let target_row = end_row.saturating_sub(rows_below);
            let target_col = cur_col.min(cols.saturating_sub(1));
            let cup = format!("\x1b[{};{}H", target_row + 1, target_col + 1);
            new_parser.process(cup.as_bytes());
        } else if cur_col != cur_row_content_len {
            let new_screen = new_parser.screen();
            let mut new_logical_start = new_screen.cursor_position().0;
            while new_logical_start > 0 && new_screen.row_wrapped(new_logical_start - 1) {
                new_logical_start -= 1;
            }
            let target_row = (new_logical_start as usize + logical_cur_col / cols as usize)
                .min(rows.saturating_sub(1) as usize) as u16;
            let target_col = (logical_cur_col % cols as usize) as u16;
            let cup = format!("\x1b[{};{}H", target_row + 1, target_col + 1);
            new_parser.process(cup.as_bytes());
        }

        if !input_modes.is_empty() {
            new_parser.process(input_modes.as_bytes());
        }
        if !attrs.is_empty() {
            new_parser.process(attrs.as_bytes());
        }
        if hide_cursor {
            new_parser.process(b"\x1b[?25l");
        }

        self.parser = new_parser;
    }

    pub fn clear_selection(&mut self) {
        self.selection = None;
        self.selection_mode = TerminalSelectionMode::Char;
        self.is_selecting = false;
        self.drag_mouse_pos = None;
        self.drag_scroll_active = false;
    }

    /// Lowest absolute row index still retained in the active screen/scrollback buffer.
    pub fn min_abs_row(&self) -> usize {
        if self.parser.screen().alternate_screen() {
            0
        } else {
            self.parser.callbacks().discarded_rows()
        }
    }

    /// Exclusive upper bound of absolute row indices currently in the active screen/scrollback.
    pub fn max_abs_row_excl(&self) -> usize {
        let screen = self.parser.screen();
        let rows = screen.size().0.get() as usize;
        if screen.alternate_screen() {
            rows
        } else {
            self.parser
                .callbacks()
                .discarded_rows()
                .saturating_add(screen.scrollback_len())
                .saturating_add(rows)
        }
    }

    /// Absolute row index corresponding to visible viewport row `0` at the current scrollback offset.
    pub fn visible_base_abs_row(&self) -> usize {
        self.parser
            .callbacks()
            .visible_base_abs_row(self.parser.screen())
    }

    /// Converts a visible viewport row `0..rows` into a buffer-anchored absolute row index.
    pub fn vis_row_to_abs(&self, vis_row: u16) -> usize {
        self.visible_base_abs_row()
            .saturating_add(vis_row as usize)
    }

    /// Converts a buffer-anchored absolute row index into its current visible row, if on-screen.
    pub fn abs_row_to_vis(&self, abs_row: usize) -> Option<u16> {
        let base = self.visible_base_abs_row();
        let rows = self.parser.screen().size().0.get() as usize;
        if abs_row >= base && abs_row < base + rows {
            Some((abs_row - base) as u16)
        } else {
            None
        }
    }

    /// Returns whether the currently visible cell `(vis_row, col)` is highlighted by selection.
    #[cfg(test)]
    pub fn is_cell_selected_visible(&self, vis_row: u16, col: u16) -> bool {
        let is_alt = self.parser.screen().alternate_screen();
        let abs_row = self.vis_row_to_abs(vis_row);
        self.selection
            .is_some_and(|sel| sel.contains(is_alt, abs_row, col))
    }

    /// Fast O(1) check for whether there is a non-empty valid selection on the active screen.
    pub fn has_selection(&self) -> bool {
        let Some(sel) = self.selection else {
            return false;
        };
        if sel.is_empty() || sel.is_alt != self.parser.screen().alternate_screen() {
            return false;
        }
        let (start, end) = sel.ordered();
        let min_abs = self.min_abs_row();
        let max_abs_excl = self.max_abs_row_excl();
        max_abs_excl > min_abs && end.abs_row >= min_abs && start.abs_row < max_abs_excl
    }

    /// Trims or clears selection if older rows were evicted from the scrollback ring buffer.
    fn clamp_or_clear_selection(&mut self) {
        let Some(mut sel) = self.selection else {
            return;
        };
        let screen = self.parser.screen();
        let is_alt = screen.alternate_screen();
        if sel.is_alt != is_alt {
            self.clear_selection();
            return;
        }
        let min_abs = self.min_abs_row();
        let max_abs_excl = self.max_abs_row_excl();
        if max_abs_excl <= min_abs {
            self.clear_selection();
            return;
        }
        let max_abs = max_abs_excl - 1;
        let cols = screen.size().1.get();

        let (lo, hi) = sel.ordered();
        if hi.abs_row < min_abs || lo.abs_row > max_abs {
            self.clear_selection();
            return;
        }

        let clamp_pos = |pos: TerminalPos| -> TerminalPos {
            if pos.abs_row < min_abs {
                TerminalPos {
                    abs_row: min_abs,
                    col: 0,
                }
            } else if pos.abs_row > max_abs {
                TerminalPos {
                    abs_row: max_abs,
                    col: cols,
                }
            } else {
                TerminalPos {
                    abs_row: pos.abs_row,
                    col: pos.col.min(cols),
                }
            }
        };

        sel.start = clamp_pos(sel.start);
        sel.end = clamp_pos(sel.end);

        match &mut self.selection_mode {
            TerminalSelectionMode::Char => {}
            TerminalSelectionMode::Word {
                anchor_start,
                anchor_end,
            } => {
                *anchor_start = clamp_pos(*anchor_start);
                *anchor_end = clamp_pos(*anchor_end);
            }
            TerminalSelectionMode::Line {
                anchor_start_row,
                anchor_end_row,
            } => {
                *anchor_start_row = (*anchor_start_row).clamp(min_abs, max_abs);
                *anchor_end_row = (*anchor_end_row).clamp(min_abs, max_abs);
            }
        }

        if sel.is_empty() && !self.is_selecting {
            self.clear_selection();
        } else {
            self.selection = Some(sel);
        }
    }

    pub fn scrollback_offset(&self) -> usize {
        self.parser.screen().scrollback()
    }

    pub fn scroll_to_bottom(&mut self) {
        if self.parser.screen().scrollback() > 0 {
            self.parser.screen_mut().set_scrollback(0);
        }
    }

    pub fn scroll_lines(&mut self, delta_lines: i32) {
        let screen = self.parser.screen_mut();
        let current = screen.scrollback() as i32;
        let max_scroll = screen.scrollback_len() as i32;
        let next = (current + delta_lines).clamp(0, max_scroll) as usize;
        screen.set_scrollback(next);
    }

    fn measured_cell_width(&self, font_size: f32) -> f32 {
        self.cell_width
            .lock()
            .ok()
            .map(|g| *g)
            .filter(|w| *w > 2.0)
            .unwrap_or(font_size * 0.60)
    }

    /// Strict cell hit-test: returns `Some((vis_row, col))` only when `pos` lies inside
    /// the rendered character grid (used for URL hover & Ctrl+Click).
    pub fn pixel_to_cell(&self, pos: Point<Pixels>, font_size: f32) -> Option<(u16, u16)> {
        let bounds = (*self.screen_bounds.lock().ok()?)?;
        let cw = self.measured_cell_width(font_size);
        let lh = terminal_line_height_scaled(font_size, self.line_height_mult);
        let (rows_nz, cols_nz) = self.parser.screen().size();
        let rows = rows_nz.get();
        let cols = cols_nz.get();

        let dx = f32::from(pos.x) - f32::from(bounds.origin.x);
        let dy = f32::from(pos.y) - f32::from(bounds.origin.y);
        if dx < 0.0 || dy < 0.0 || dx >= cols as f32 * cw || dy >= rows as f32 * lh {
            return None;
        }

        let row = ((dy / lh).floor() as u16).min(rows.saturating_sub(1));
        let col = ((dx / cw).floor() as u16).min(cols.saturating_sub(1));
        Some((row, col))
    }

    /// Clamped cell hit-test for double/triple-click and word/line drag tracking.
    pub fn pixel_to_cell_clamped(&self, pos: Point<Pixels>, font_size: f32) -> Option<(u16, u16)> {
        let bounds = (*self.screen_bounds.lock().ok()?)?;
        let cw = self.measured_cell_width(font_size);
        let lh = terminal_line_height_scaled(font_size, self.line_height_mult);
        let (rows_nz, cols_nz) = self.parser.screen().size();
        let rows = rows_nz.get();
        let cols = cols_nz.get();

        let dx = (f32::from(pos.x) - f32::from(bounds.origin.x)).max(0.0);
        let dy = (f32::from(pos.y) - f32::from(bounds.origin.y)).max(0.0);

        let row = ((dy / lh).floor() as u16).min(rows.saturating_sub(1));
        let col = ((dx / cw).floor() as u16).min(cols.saturating_sub(1));
        Some((row, col))
    }

    /// Half-cell character-boundary hit-test in `0..=cols` for precise drag selection.
    ///
    /// When dragging above the top edge of the viewport, snaps to the start of row 0 (`col = 0`);
    /// when dragging below the bottom edge, snaps to the end of the last row (`col = cols`).
    pub fn pixel_to_boundary_clamped(
        &self,
        pos: Point<Pixels>,
        font_size: f32,
    ) -> Option<(u16, u16)> {
        let bounds = (*self.screen_bounds.lock().ok()?)?;
        let cw = self.measured_cell_width(font_size);
        let lh = terminal_line_height_scaled(font_size, self.line_height_mult);
        let (rows_nz, cols_nz) = self.parser.screen().size();
        let rows = rows_nz.get();
        let cols = cols_nz.get();
        let grid_h = rows as f32 * lh;

        let dx = f32::from(pos.x) - f32::from(bounds.origin.x);
        let dy = f32::from(pos.y) - f32::from(bounds.origin.y);

        if dy < 0.0 {
            return Some((0, 0));
        }
        if dy >= grid_h {
            return Some((rows.saturating_sub(1), cols));
        }

        let row = ((dy / lh).floor() as u16).min(rows.saturating_sub(1));
        let col = (dx / cw).round().clamp(0.0, cols as f32) as u16;
        Some((row, col))
    }

    /// If the drag pointer is above or below the rendered terminal grid, returns the scroll
    /// delta in lines (`> 0` scrolls up into scrollback, `< 0` scrolls down toward live output).
    pub fn drag_scroll_step(&self, pos: Point<Pixels>, font_size: f32) -> Option<i32> {
        if self.parser.screen().alternate_screen() {
            return None;
        }
        let bounds = (*self.screen_bounds.lock().ok()?)?;
        let lh = terminal_line_height_scaled(font_size, self.line_height_mult);
        let rows = self.parser.screen().size().0.get();
        let top = f32::from(bounds.origin.y);
        let bottom = top + rows as f32 * lh;
        let y = f32::from(pos.y);

        if y < top {
            let overflow = top - y;
            let lines = ((overflow / lh).ceil() as i32).clamp(1, 5);
            Some(lines)
        } else if y > bottom {
            let overflow = y - bottom;
            let lines = ((overflow / lh).ceil() as i32).clamp(1, 5);
            Some(-lines)
        } else {
            None
        }
    }

    /// Starts a single-click (or Shift+Click extending) character selection at pixel `pos`.
    pub fn begin_char_selection(
        &mut self,
        pos: Point<Pixels>,
        font_size: f32,
        extend_shift: bool,
    ) {
        let Some((vis_row, boundary_col)) = self.pixel_to_boundary_clamped(pos, font_size) else {
            self.clear_selection();
            return;
        };
        let is_alt = self.parser.screen().alternate_screen();
        let target = TerminalPos {
            abs_row: self.vis_row_to_abs(vis_row),
            col: boundary_col,
        };

        if extend_shift
            && let Some(existing) = self.selection
                && existing.is_alt == is_alt && !existing.is_empty() {
                    self.selection = Some(TerminalSelection {
                        start: existing.start,
                        end: target,
                        is_alt,
                    });
                    self.selection_mode = TerminalSelectionMode::Char;
                    self.is_selecting = true;
                    self.drag_mouse_pos = Some(pos);
                    return;
                }

        self.selection = Some(TerminalSelection {
            start: target,
            end: target,
            is_alt,
        });
        self.selection_mode = TerminalSelectionMode::Char;
        self.is_selecting = true;
        self.drag_mouse_pos = Some(pos);
    }

    /// Starts a double-click word selection at pixel `pos` (supports drag-extending by word).
    pub fn begin_word_selection(&mut self, pos: Point<Pixels>, font_size: f32) {
        let Some((vis_row, col)) = self.pixel_to_cell_clamped(pos, font_size) else {
            self.clear_selection();
            return;
        };
        self.select_word_at(vis_row, col);
        if let Some(sel) = self.selection {
            self.selection_mode = TerminalSelectionMode::Word {
                anchor_start: sel.start,
                anchor_end: sel.end,
            };
            self.is_selecting = true;
            self.drag_mouse_pos = Some(pos);
        }
    }

    /// Starts a triple-click logical line selection at pixel `pos` (supports drag-extending by line).
    pub fn begin_line_selection(&mut self, pos: Point<Pixels>, font_size: f32) {
        let Some((vis_row, _)) = self.pixel_to_cell_clamped(pos, font_size) else {
            self.clear_selection();
            return;
        };
        self.select_line(vis_row);
        if let Some(sel) = self.selection {
            self.selection_mode = TerminalSelectionMode::Line {
                anchor_start_row: sel.start.abs_row,
                anchor_end_row: sel.end.abs_row,
            };
            self.is_selecting = true;
            self.drag_mouse_pos = Some(pos);
        }
    }

    /// Updates an in-progress drag selection to pixel `pos`. Returns `true` if selection changed.
    pub fn update_selection_drag(&mut self, pos: Point<Pixels>, font_size: f32) -> bool {
        if !self.is_selecting {
            return false;
        }
        self.drag_mouse_pos = Some(pos);
        let is_alt = self.parser.screen().alternate_screen();
        let cols = self.parser.screen().size().1.get();
        let prev = self.selection;

        match self.selection_mode {
            TerminalSelectionMode::Char => {
                let Some((vis_row, boundary_col)) = self.pixel_to_boundary_clamped(pos, font_size)
                else {
                    return false;
                };
                let target = TerminalPos {
                    abs_row: self.vis_row_to_abs(vis_row),
                    col: boundary_col,
                };
                if let Some(ref mut sel) = self.selection
                    && sel.is_alt == is_alt {
                        sel.end = target;
                    }
            }
            TerminalSelectionMode::Word {
                anchor_start,
                anchor_end,
            } => {
                let Some((vis_row, col)) = self.pixel_to_cell_clamped(pos, font_size) else {
                    return false;
                };
                let (w_start, w_end) = self.word_bounds_at(vis_row, col);
                let (start, end) = if w_start < anchor_start {
                    (anchor_end, w_start)
                } else if w_end > anchor_end {
                    (anchor_start, w_end)
                } else {
                    (anchor_start, anchor_end)
                };
                self.selection = Some(TerminalSelection { start, end, is_alt });
            }
            TerminalSelectionMode::Line {
                anchor_start_row,
                anchor_end_row,
            } => {
                let Some((vis_row, _)) = self.pixel_to_cell_clamped(pos, font_size) else {
                    return false;
                };
                let abs_row = self.vis_row_to_abs(vis_row);
                let (l_start, l_end) = self.logical_line_bounds(abs_row);
                let start_row = anchor_start_row.min(l_start);
                let end_row = anchor_end_row.max(l_end);
                self.selection = Some(TerminalSelection {
                    start: TerminalPos {
                        abs_row: start_row,
                        col: 0,
                    },
                    end: TerminalPos {
                        abs_row: end_row,
                        col: cols,
                    },
                    is_alt,
                });
            }
        }

        self.selection != prev
    }

    /// Finalizes a drag selection on mouse release. Clears empty zero-width anchor selections.
    pub fn finish_selection(&mut self) -> bool {
        if !self.is_selecting {
            return false;
        }
        self.is_selecting = false;
        self.drag_mouse_pos = None;
        self.drag_scroll_active = false;
        if let Some(sel) = self.selection
            && sel.is_empty() {
                self.selection = None;
            }
        true
    }

    /// Returns whether the buffer row at `abs_row` soft-wraps onto `abs_row + 1`.
    fn row_wrapped_at_abs(&mut self, abs_row: usize) -> bool {
        let min_abs = self.min_abs_row();
        let max_abs_excl = self.max_abs_row_excl();
        if abs_row < min_abs || abs_row >= max_abs_excl {
            return false;
        }
        if let Some(vis_r) = self.abs_row_to_vis(abs_row) {
            return self.parser.screen().row_wrapped(vis_r);
        }
        let saved_offset = self.parser.screen().scrollback();
        let live_top_abs = min_abs.saturating_add(self.parser.screen().scrollback_len());
        let target_offset = live_top_abs.saturating_sub(abs_row);
        self.parser.screen_mut().set_scrollback(target_offset);
        let wrapped = self
            .abs_row_to_vis(abs_row)
            .is_some_and(|vis_r| self.parser.screen().row_wrapped(vis_r));
        self.parser.screen_mut().set_scrollback(saved_offset);
        wrapped
    }

    /// Finds the inclusive `(start_abs_row, end_abs_row)` of the soft-wrapped logical line
    /// containing `abs_row`.
    fn logical_line_bounds(&mut self, abs_row: usize) -> (usize, usize) {
        let min_abs = self.min_abs_row();
        let max_abs_excl = self.max_abs_row_excl();
        if max_abs_excl <= min_abs {
            return (abs_row, abs_row);
        }
        let clamped = abs_row.clamp(min_abs, max_abs_excl - 1);
        let saved_offset = self.parser.screen().scrollback();

        let mut start = clamped;
        while start > min_abs && self.row_wrapped_at_abs(start - 1) {
            start -= 1;
        }
        let mut end = clamped;
        while end + 1 < max_abs_excl && self.row_wrapped_at_abs(end) {
            end += 1;
        }

        if self.parser.screen().scrollback() != saved_offset {
            self.parser.screen_mut().set_scrollback(saved_offset);
        }
        (start, end)
    }

    /// Computes buffer-anchored `(start, end)` half-open word bounds around visible `(vis_row, col)`.
    fn word_bounds_at(&mut self, vis_row: u16, col: u16) -> (TerminalPos, TerminalPos) {
        let (rows_nz, cols_nz) = self.parser.screen().size();
        let rows = rows_nz.get();
        let cols = cols_nz.get();
        let vis_row = vis_row.min(rows.saturating_sub(1));
        let mut col = col.min(cols.saturating_sub(1));

        let screen = self.parser.screen();
        if screen
            .cell(vis_row, col)
            .is_some_and(|c| c.is_wide_continuation())
            && col > 0
        {
            col -= 1;
        }

        let target_class = cell_char_class(screen.cell(vis_row, col));
        let abs_row = self.vis_row_to_abs(vis_row);

        if target_class == CellCharClass::Delimiter {
            let width = if screen.cell(vis_row, col).is_some_and(|c| c.is_wide()) {
                2
            } else {
                1
            };
            return (
                TerminalPos { abs_row, col },
                TerminalPos {
                    abs_row,
                    col: (col + width).min(cols),
                },
            );
        }

        let cell_class_at_vis = |screen: &vt100::Screen, r: u16, c: u16| -> CellCharClass {
            let effective_c = if screen
                .cell(r, c)
                .is_some_and(|cell| cell.is_wide_continuation())
                && c > 0
            {
                c - 1
            } else {
                c
            };
            cell_char_class(screen.cell(r, effective_c))
        };

        let mut start_vis = vis_row;
        let mut start_col = col;
        loop {
            while start_col > 0 && cell_class_at_vis(screen, start_vis, start_col - 1) == target_class
            {
                start_col -= 1;
                if screen
                    .cell(start_vis, start_col)
                    .is_some_and(|c| c.is_wide_continuation())
                    && start_col > 0
                {
                    start_col -= 1;
                }
            }
            if target_class == CellCharClass::Word
                && start_col == 0
                && start_vis > 0
                && screen.row_wrapped(start_vis - 1)
                && cell_class_at_vis(screen, start_vis - 1, cols.saturating_sub(1)) == target_class
            {
                start_vis -= 1;
                start_col = cols.saturating_sub(1);
                if screen
                    .cell(start_vis, start_col)
                    .is_some_and(|c| c.is_wide_continuation())
                    && start_col > 0
                {
                    start_col -= 1;
                }
            } else {
                break;
            }
        }

        let mut end_vis = vis_row;
        let mut end_col = col;
        loop {
            while end_col < cols && cell_class_at_vis(screen, end_vis, end_col) == target_class {
                let step = if screen.cell(end_vis, end_col).is_some_and(|c| c.is_wide()) {
                    2
                } else {
                    1
                };
                end_col = (end_col + step).min(cols);
            }
            if target_class == CellCharClass::Word
                && end_col == cols
                && end_vis + 1 < rows
                && screen.row_wrapped(end_vis)
                && cell_class_at_vis(screen, end_vis + 1, 0) == target_class
            {
                end_vis += 1;
                end_col = 0;
            } else {
                break;
            }
        }

        (
            TerminalPos {
                abs_row: self.vis_row_to_abs(start_vis),
                col: start_col,
            },
            TerminalPos {
                abs_row: self.vis_row_to_abs(end_vis),
                col: end_col,
            },
        )
    }

    /// Double-click helper: selects the word around visible `(row, col)` anchored to buffer rows.
    pub fn select_word_at(&mut self, row: u16, col: u16) {
        let is_alt = self.parser.screen().alternate_screen();
        let (start, end) = self.word_bounds_at(row, col);
        self.selection = Some(TerminalSelection { start, end, is_alt });
    }

    /// Triple-click helper: selects the full logical line (including soft-wrapped continuations)
    /// containing visible `row`, anchored to buffer rows.
    pub fn select_line(&mut self, row: u16) {
        let is_alt = self.parser.screen().alternate_screen();
        let (rows_nz, cols_nz) = self.parser.screen().size();
        let vis_row = row.min(rows_nz.get().saturating_sub(1));
        let cols = cols_nz.get();
        let abs_row = self.vis_row_to_abs(vis_row);
        let (start_row, end_row) = self.logical_line_bounds(abs_row);
        self.selection = Some(TerminalSelection {
            start: TerminalPos {
                abs_row: start_row,
                col: 0,
            },
            end: TerminalPos {
                abs_row: end_row,
                col: cols,
            },
            is_alt,
        });
    }

    /// Extracts plain text covered by the current buffer-anchored selection across both
    /// visible rows and off-screen scrollback, joining soft-wrapped lines cleanly and
    /// restoring the caller's exact scrollback position.
    pub fn selected_text(&mut self) -> Option<String> {
        let sel = self.selection?;
        if sel.is_empty() {
            return None;
        }
        let is_alt = self.parser.screen().alternate_screen();
        if sel.is_alt != is_alt {
            return None;
        }

        let (start_pos, end_pos) = sel.ordered();
        let (rows_nz, cols_nz) = self.parser.screen().size();
        let rows = rows_nz.get() as usize;
        let cols = cols_nz.get();
        let min_abs = self.min_abs_row();
        let max_abs_excl = self.max_abs_row_excl();
        if max_abs_excl <= min_abs
            || end_pos.abs_row < min_abs
            || start_pos.abs_row >= max_abs_excl
        {
            return None;
        }

        let (sr, sc) = if start_pos.abs_row < min_abs {
            (min_abs, 0)
        } else {
            (start_pos.abs_row, start_pos.col.min(cols))
        };
        let (er, ec) = if end_pos.abs_row >= max_abs_excl {
            (max_abs_excl - 1, cols)
        } else {
            (end_pos.abs_row, end_pos.col.min(cols))
        };
        if (sr, sc) >= (er, ec) {
            return None;
        }

        let saved_offset = self.parser.screen().scrollback();
        let live_top_abs = if is_alt {
            0
        } else {
            min_abs.saturating_add(self.parser.screen().scrollback_len())
        };

        let mut out = String::new();
        let mut cur = sr;
        while cur <= er {
            let vis_base = self.visible_base_abs_row();
            if !(cur >= vis_base && cur < vis_base + rows) {
                let target_offset = live_top_abs.saturating_sub(cur);
                self.parser.screen_mut().set_scrollback(target_offset);
            }
            let vis_base = self.visible_base_abs_row();
            let window_end = (vis_base + rows - 1).min(er);
            let screen = self.parser.screen();

            for abs_r in cur..=window_end {
                let vis_r = (abs_r - vis_base) as u16;
                let c_start = if abs_r == sr { sc } else { 0 };
                let c_end = if abs_r == er { ec } else { cols };
                let wrapped = screen.row_wrapped(vis_r);

                let mut last_non_space_end: u16 = 0;
                for c in (0..cols).rev() {
                    if let Some(cell) = screen.cell(vis_r, c)
                        && (cell.is_wide_continuation()
                            || (cell.has_contents()
                                && !cell.contents().chars().all(|ch| ch.is_whitespace())))
                        {
                            last_non_space_end = c + 1;
                            break;
                        }
                }

                let mut row_text = String::new();
                for c in c_start..c_end {
                    if let Some(cell) = screen.cell(vis_r, c) {
                        if cell.is_wide_continuation() {
                            if c == c_start && c > 0
                                && let Some(prev) = screen.cell(vis_r, c - 1)
                                    && prev.is_wide() && prev.has_contents() {
                                        row_text.push_str(prev.contents());
                                    }
                            continue;
                        }
                        if cell.has_contents() {
                            row_text.push_str(cell.contents());
                        } else {
                            row_text.push(' ');
                        }
                    } else {
                        row_text.push(' ');
                    }
                }

                let continue_wrapped = abs_r < er && wrapped && c_end == cols;
                if !continue_wrapped && c_end > last_non_space_end {
                    let trimmed_len = row_text.trim_end_matches(' ').len();
                    row_text.truncate(trimmed_len);
                }

                out.push_str(&row_text);
                if abs_r < er && !continue_wrapped {
                    out.push('\n');
                }
            }

            cur = window_end + 1;
        }

        if self.parser.screen().scrollback() != saved_offset {
            self.parser.screen_mut().set_scrollback(saved_offset);
        }

        if out.trim().is_empty() {
            None
        } else {
            Some(out)
        }
    }

    /// Detects either an OSC 8 hyperlink OR a single/multi-line wrapped `http(s)://` URL at `(row, col)`.
    pub fn url_at(&self, row: u16, col: u16) -> Option<HoveredUrl> {
        let screen = self.parser.screen();
        let (rows_nz, cols_nz) = screen.size();
        let rows = rows_nz.get();
        let cols = cols_nz.get();
        if row >= rows || col >= cols {
            return None;
        }

        // 1. Prefer explicit OSC 8 hyperlinks (e.g. "→ Click here to authenticate"), including in scrollback
        if let Some(osc_link) = self.parser.callbacks().find_at(screen, row, col) {
            return Some(osc_link);
        }

        // 2. Snapshot visible rows and detect single-line AND multi-line wrapped URLs
        let mut grid_rows: Vec<Vec<char>> = Vec::with_capacity(rows as usize);
        for r in 0..rows {
            let mut row_chars = Vec::with_capacity(cols as usize);
            for c in 0..cols {
                let ch = screen
                    .cell(r, c)
                    .and_then(|cell| cell.contents().chars().next())
                    .unwrap_or(' ');
                row_chars.push(ch);
            }
            grid_rows.push(row_chars);
        }

        find_url_in_grid(&grid_rows, row, col)
    }

    /// Renders all visible VT100 rows using GPUI `StyledText` with coalesced ANSI highlights,
    /// live selection highlighting, and hovered multi-line/OSC-8 URL underlines.
    pub fn render_screen(
        &self,
        t: &ThemePalette,
        font_family: &str,
        font_size: f32,
        cursor_style: TerminalCursorStyle,
        is_focused: bool,
        ui_tx: mpsc::UnboundedSender<UiEvent>,
    ) -> impl IntoElement {
        let (term_bg, term_fg, term_cur) = self
            .theme_id
            .as_deref()
            .and_then(TerminalThemeId::from_slug)
            .map(|tid| {
                let (bg, fg, cur) = tid.colors();
                (gpui::rgb(bg).into(), gpui::rgb(fg).into(), gpui::rgb(cur).into())
            })
            .unwrap_or((t.terminal_bg, t.terminal_fg, t.terminal_cursor));

        let screen = self.parser.screen();
        let (rows_nz, cols_nz) = screen.size();
        let rows: u16 = rows_nz.get();
        let cols: u16 = cols_nz.get();
        let is_alt = screen.alternate_screen();
        let visible_base_abs = self.visible_base_abs_row();
        let (cur_row, cur_col) = screen.cursor_position();
        let show_cursor = !screen.hide_cursor() && self.connected && screen.scrollback() == 0;
        let line_h = terminal_line_height_scaled(font_size, self.line_height_mult);
        let selection = self.selection;
        let hovered_url = self.hovered_url.as_ref();
        let sel_bg = t.accent.opacity(0.36);
        let match_bg = t.warning.opacity(0.32);
        let active_match_bg = t.warning.opacity(0.70);
        let active_match = self.search_matches.get(self.active_match_idx).copied();

        let mut row_elements = Vec::with_capacity(rows as usize);

        for r in 0..rows {
            let row_abs = visible_base_abs.saturating_add(r as usize);
            let mut text = String::with_capacity(cols as usize);
            let mut highlights: Vec<(Range<usize>, HighlightStyle)> = Vec::new();

            for c in 0..cols {
                let cell = screen.cell(r, c);
                if cell.is_some_and(|cell| cell.is_wide_continuation()) {
                    continue;
                }
                let is_wide = cell.is_some_and(|cell| cell.is_wide());
                let is_cursor = show_cursor
                    && r == cur_row
                    && (c == cur_col || (is_wide && c + 1 == cur_col));
                let is_selected = selection.is_some_and(|sel| {
                    sel.contains(is_alt, row_abs, c)
                        || (is_wide && sel.contains(is_alt, row_abs, c + 1))
                });
                let is_active_match = active_match.is_some_and(|(mr, msc, mec)| {
                    mr == row_abs && c >= msc && c < mec
                });
                let is_search_match = !is_active_match
                    && !self.search_matches.is_empty()
                    && self
                        .search_matches
                        .iter()
                        .any(|&(mr, msc, mec)| mr == row_abs && c >= msc && c < mec);
                let is_hovered_link = hovered_url
                    .is_some_and(|u| u.contains(r, c) || (is_wide && u.contains(r, c + 1)));

                let ch_str = match cell {
                    Some(cell) => {
                        let contents = cell.contents();
                        if contents.is_empty() {
                            " "
                        } else {
                            contents
                        }
                    }
                    None => " ",
                };

                let start = text.len();
                text.push_str(ch_str);
                let end = text.len();

                if is_cursor {
                    let cur_color = if is_focused { term_cur } else { t.text_muted };
                    let cur_style = match cursor_style {
                        TerminalCursorStyle::Block => HighlightStyle {
                            color: Some(term_bg),
                            background_color: Some(cur_color),
                            font_weight: Some(FontWeight::BOLD),
                            ..Default::default()
                        },
                        TerminalCursorStyle::Underline => HighlightStyle {
                            color: Some(term_fg),
                            underline: Some(UnderlineStyle {
                                thickness: px(2.0),
                                color: Some(cur_color),
                                wavy: false,
                            }),
                            ..Default::default()
                        },
                        TerminalCursorStyle::Bar => HighlightStyle {
                            color: Some(term_fg),
                            background_color: Some(cur_color.opacity(0.45)),
                            underline: Some(UnderlineStyle {
                                thickness: px(2.0),
                                color: Some(cur_color),
                                wavy: false,
                            }),
                            ..Default::default()
                        },
                    };
                    highlights.push((start..end, cur_style));
                    continue;
                }

                if let Some(cell) = cell {
                    let mut fg = vt_color_to_hsla(cell.fgcolor(), term_fg);
                    let mut bg = match cell.bgcolor() {
                        vt100::Color::Default => None,
                        other => Some(vt_color_to_hsla(other, term_bg)),
                    };

                    if cell.inverse() {
                        let old_fg = fg;
                        fg = bg.unwrap_or(term_bg);
                        bg = Some(old_fg);
                    }

                    if is_active_match {
                        fg = term_bg;
                        bg = Some(active_match_bg);
                    } else if is_search_match {
                        bg = Some(match_bg);
                    }

                    if is_selected {
                        if cell.inverse() && cell.bgcolor() == vt100::Color::Default {
                            fg = vt_color_to_hsla(cell.fgcolor(), term_fg);
                        }
                        bg = Some(sel_bg);
                    }
                    if is_hovered_link {
                        fg = t.accent;
                    }

                    let has_custom = cell.fgcolor() != vt100::Color::Default
                        || bg.is_some()
                        || cell.bold()
                        || cell.underline()
                        || is_hovered_link
                        || self.theme_id.is_some();

                    if has_custom {
                        let style = HighlightStyle {
                            color: Some(fg),
                            background_color: bg,
                            font_weight: if cell.bold() {
                                Some(FontWeight::BOLD)
                            } else {
                                None
                            },
                            underline: if cell.underline() || is_hovered_link {
                                Some(UnderlineStyle {
                                    thickness: px(1.0),
                                    color: Some(fg),
                                    wavy: false,
                                })
                            } else {
                                None
                            },
                            ..Default::default()
                        };

                        if let Some((last_range, last_style)) = highlights.last_mut() {
                            if last_range.end == start && *last_style == style {
                                last_range.end = end;
                            } else {
                                highlights.push((start..end, style));
                            }
                        } else {
                            highlights.push((start..end, style));
                        }
                    }
                } else if is_selected {
                    let style = HighlightStyle {
                        background_color: Some(sel_bg),
                        ..Default::default()
                    };
                    if let Some((last_range, last_style)) = highlights.last_mut() {
                        if last_range.end == start && *last_style == style {
                            last_range.end = end;
                        } else {
                            highlights.push((start..end, style));
                        }
                    } else {
                        highlights.push((start..end, style));
                    }
                }
            }

            let styled = if highlights.is_empty() {
                StyledText::new(text)
            } else {
                StyledText::new(text).with_highlights(highlights)
            };

            row_elements.push(
                div()
                    .w_full()
                    .h(px(line_h))
                    .flex_shrink_0()
                    .line_height(px(line_h))
                    .whitespace_nowrap()
                    .child(styled),
            );
        }

        let bounds_ref = Arc::clone(&self.screen_bounds);
        let cw_ref = Arc::clone(&self.cell_width);
        let last_req_ref = Arc::clone(&self.last_requested_size);
        let font_name = font_family.to_string();
        let tab_id = self.tab_id.clone();
        let cur_cols = self.cols;
        let cur_rows = self.rows;

        let metrics_tracker = canvas(
            move |bounds, window, _cx| {
                if let Ok(mut b) = bounds_ref.lock() {
                    *b = Some(bounds);
                }
                let mut measured_cw = cw_ref
                    .lock()
                    .ok()
                    .map(|g| *g)
                    .filter(|w| *w > 2.0)
                    .unwrap_or(font_size * 0.60);

                // Measure shaped run width across 64 monospace cells so pixel-to-column
                // mapping matches GPUI StyledText layout without cumulative drift.
                let sample: SharedString = "M".repeat(64).into();
                let run = TextRun {
                    len: sample.len(),
                    font: font(font_name.clone()),
                    color: gpui::white(),
                    background_color: None,
                    underline: None,
                    strikethrough: None,
                };
                let shaped = window
                    .text_system()
                    .shape_line(sample, px(font_size), &[run], None);
                let shaped_w = f32::from(shaped.width) / 64.0;
                if shaped_w > 2.0 {
                    measured_cw = shaped_w;
                    if let Ok(mut cw) = cw_ref.lock() {
                        *cw = shaped_w;
                    }
                } else {
                    let fid = window.text_system().resolve_font(&font(font_name));
                    if let Ok(adv) = window.text_system().advance(fid, px(font_size), 'M') {
                        let w = f32::from(adv.width);
                        if w > 2.0 {
                            measured_cw = w;
                            if let Ok(mut cw) = cw_ref.lock() {
                                *cw = w;
                            }
                        }
                    }
                }

                let avail_w = f32::from(bounds.size.width);
                let avail_h = f32::from(bounds.size.height);
                if avail_w >= measured_cw * 4.0 && avail_h >= line_h * 2.0 {
                    let target_cols = (avail_w / measured_cw).floor().clamp(20.0, 400.0) as u16;
                    let target_rows = (avail_h / line_h).floor().clamp(4.0, 200.0) as u16;
                    if target_cols != cur_cols || target_rows != cur_rows {
                        let should_send = match last_req_ref.lock() {
                            Ok(mut last) => {
                                if *last != (target_cols, target_rows) {
                                    *last = (target_cols, target_rows);
                                    true
                                } else {
                                    false
                                }
                            }
                            Err(_) => true,
                        };
                        if should_send {
                            let _ = ui_tx.send(UiEvent::TerminalResize {
                                tab_id: tab_id.clone(),
                                cols: target_cols,
                                rows: target_rows,
                            });
                        }
                    }
                }
            },
            |_bounds, _, _window, _cx| {},
        )
        .absolute()
        .inset_0();

        div()
            .relative()
            .flex_1()
            .min_h_0()
            .min_w_0()
            .w_full()
            .overflow_hidden()
            .flex()
            .flex_col()
            .font_family(font_family.to_string())
            .text_size(px(font_size))
            .text_color(t.terminal_fg)
            .children(row_elements)
            .child(metrics_tracker)
    }
}

fn is_url_char(ch: char) -> bool {
    !ch.is_whitespace()
        && !matches!(ch, '<' | '>' | '"' | '\'' | '`')
        && !('\u{2500}'..='\u{257F}').contains(&ch)
}

/// Returns `(first_non_space_col, last_non_space_col_exclusive)` if the row has non-space content.
fn row_non_space_bounds(chars: &[char]) -> Option<(usize, usize)> {
    let first = chars.iter().position(|c| !c.is_whitespace())?;
    let last = chars.iter().rposition(|c| !c.is_whitespace())?;
    Some((first, last + 1))
}

/// Finds a single-line or multi-line wrapped `http://` / `https://` URL covering `(target_row, target_col)`.
fn find_url_in_grid(
    grid: &[Vec<char>],
    target_row: u16,
    target_col: u16,
) -> Option<HoveredUrl> {
    let total_rows = grid.len();
    for r in 0..total_rows {
        let chars = &grid[r];
        let line: String = chars.iter().collect();
        let mut search_from = 0usize;

        while search_from < line.len() {
            let rest = &line[search_from..];
            let next_https = rest.find("https://");
            let next_http = rest.find("http://");
            let rel = match (next_https, next_http) {
                (Some(a), Some(b)) => a.min(b),
                (Some(a), None) => a,
                (None, Some(b)) => b,
                (None, None) => break,
            };

            let start_byte = search_from + rel;
            let start_col = line[..start_byte].chars().count();

            let mut end_col = start_col;
            while end_col < chars.len() && is_url_char(chars[end_col]) {
                end_col += 1;
            }

            let mut spans: Vec<(u16, u16, u16)> = Vec::new();
            let mut full_url = String::new();
            if end_col > start_col {
                spans.push((r as u16, start_col as u16, (end_col - 1) as u16));
                full_url.extend(&chars[start_col..end_col]);
            }

            // Check if the URL ran all the way to the last non-space char on row `r`
            // (covers both terminal soft-wrap AND CLI hard-wrap at e.g. 80 cols).
            let reached_row_content_end = row_non_space_bounds(chars)
                .map(|(_, last_end)| end_col >= last_end)
                .unwrap_or(false);

            if reached_row_content_end {
                let mut next_r = r + 1;
                while next_r < total_rows {
                    let next_chars = &grid[next_r];
                    let Some((nf, nl)) = row_non_space_bounds(next_chars) else {
                        break;
                    };
                    // Continuation must start near left margin (same indent or col 0)
                    if nf > start_col.saturating_add(2) {
                        break;
                    }
                    let slice = &next_chars[nf..nl];
                    // Continuation line of a wrapped URL must be one contiguous URL token
                    // (no internal spaces/quotes) and not start a new scheme.
                    if !slice.iter().all(|&c| is_url_char(c)) {
                        break;
                    }
                    let seg: String = slice.iter().collect();
                    if seg.starts_with("http://") || seg.starts_with("https://") {
                        break;
                    }
                    // Reject horizontal divider lines (e.g. "──────────" or "==========")
                    if slice.iter().all(|&c| matches!(c, '─' | '-' | '=' | '_' | '━' | '*')) {
                        break;
                    }

                    spans.push((next_r as u16, nf as u16, (nl - 1) as u16));
                    full_url.push_str(&seg);
                    next_r += 1;
                }
            }

            // Trim trailing sentence punctuation or unmatched closing brackets from the final span
            while let Some(last_ch) = full_url.chars().last() {
                let trim = match last_ch {
                    '.' | ',' | ';' | ':' | '!' | '?' => true,
                    ')' => {
                        full_url.chars().filter(|&c| c == ')').count()
                            > full_url.chars().filter(|&c| c == '(').count()
                    }
                    ']' => {
                        full_url.chars().filter(|&c| c == ']').count()
                            > full_url.chars().filter(|&c| c == '[').count()
                    }
                    '}' => {
                        full_url.chars().filter(|&c| c == '}').count()
                            > full_url.chars().filter(|&c| c == '{').count()
                    }
                    _ => false,
                };
                if trim {
                    full_url.pop();
                    if let Some(last_span) = spans.last_mut() {
                        if last_span.2 > last_span.1 {
                            last_span.2 -= 1;
                        } else {
                            spans.pop();
                        }
                    }
                } else {
                    break;
                }
            }

            let min_len = if full_url.starts_with("https://") { 9 } else { 8 };
            if full_url.len() >= min_len && !spans.is_empty() {
                let candidate = HoveredUrl {
                    spans,
                    url: full_url,
                };
                if candidate.contains(target_row, target_col) {
                    return Some(candidate);
                }
            }

            search_from = start_byte + 7;
        }
    }
    None
}

/// Converts a GPUI `Keystroke` into bytes to transmit over the SSH PTY channel.
pub fn keystroke_to_vt_bytes(ks: &Keystroke) -> Option<Vec<u8>> {
    // Ctrl+<letter> produces ASCII control codes 0x01..0x1A
    if ks.modifiers.control && !ks.modifiers.alt && !ks.modifiers.platform
        && ks.key.len() == 1 {
            let b = ks.key.as_bytes()[0].to_ascii_lowercase();
            if b.is_ascii_lowercase() {
                return Some(vec![b - b'a' + 1]);
            }
            if b == b'[' {
                return Some(vec![0x1b]);
            }
            if b == b'\\' {
                return Some(vec![0x1c]);
            }
            if b == b']' {
                return Some(vec![0x1d]);
            }
        }

    match ks.key.as_str() {
        "enter" => Some(vec![b'\r']),
        "backspace" => Some(vec![0x7f]),
        "tab" => Some(vec![b'\t']),
        "escape" => Some(vec![0x1b]),
        "space" => Some(vec![b' ']),
        "up" => Some(b"\x1b[A".to_vec()),
        "down" => Some(b"\x1b[B".to_vec()),
        "right" => Some(b"\x1b[C".to_vec()),
        "left" => Some(b"\x1b[D".to_vec()),
        "home" => Some(b"\x1b[H".to_vec()),
        "end" => Some(b"\x1b[F".to_vec()),
        "delete" => Some(b"\x1b[3~".to_vec()),
        "pageup" => Some(b"\x1b[5~".to_vec()),
        "pagedown" => Some(b"\x1b[6~".to_vec()),
        _ => {
            if let Some(ch) = ks.key_char.as_deref()
                && !ch.is_empty() {
                    if ks.modifiers.alt {
                        let mut out = vec![0x1b];
                        out.extend_from_slice(ch.as_bytes());
                        return Some(out);
                    }
                    return Some(ch.as_bytes().to_vec());
                }
            None
        }
    }
}

/// Strips CSI/OSC ANSI escape sequences from raw PTY bytes for clean readable session transcripts.
pub fn strip_ansi_for_log(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    for ch in chars.by_ref() {
                        if ('@'..='~').contains(&ch) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    while let Some(ch) = chars.next() {
                        if ch == '\x07' {
                            break;
                        }
                        if ch == '\x1b' && chars.peek() == Some(&'\\') {
                            chars.next();
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
        } else if c != '\r' {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use gpui::Modifiers;

    #[test]
    fn encodes_ctrl_c_and_arrows() {
        let ctrl_c = Keystroke {
            modifiers: Modifiers {
                control: true,
                ..Default::default()
            },
            key: "c".into(),
            key_char: None,
        };
        assert_eq!(keystroke_to_vt_bytes(&ctrl_c), Some(vec![0x03]));

        let up = Keystroke {
            modifiers: Modifiers::default(),
            key: "up".into(),
            key_char: None,
        };
        assert_eq!(keystroke_to_vt_bytes(&up), Some(b"\x1b[A".to_vec()));
    }

    #[test]
    fn extracts_multiline_selection_and_word() {
        let mut tab = TerminalTab::connecting(
            "t1".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        tab.feed_bytes(b"\x1b[2J\x1b[Hhello world\r\nsecond line");

        let base = tab.visible_base_abs_row();
        tab.selection = Some(TerminalSelection {
            start: TerminalPos {
                abs_row: base,
                col: 6,
            },
            end: TerminalPos {
                abs_row: base + 1,
                col: 6,
            },
            is_alt: false,
        });
        assert_eq!(tab.selected_text().as_deref(), Some("world\nsecond"));

        tab.select_word_at(0, 7);
        assert_eq!(tab.selected_text().as_deref(), Some("world"));
    }

    #[test]
    fn selection_stays_tied_to_text_when_scrolling_and_offscreen() {
        let mut tab = TerminalTab::connecting(
            "t-scroll-sel".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        assert!(tab.resize(80, 10));
        tab.feed_bytes(b"\x1b[2J\x1b[H");
        for i in 0..40 {
            tab.feed_bytes(format!("ROW_{i:02}_ALPHA BETA\r\n").as_bytes());
        }
        // At scrollback == 0, visible row 5 holds some ROW_XX line.
        let target_vis_row: u16 = 5;
        let expected_line = (0..12)
            .filter_map(|c| tab.parser.screen().cell(target_vis_row, c))
            .map(|c| c.contents())
            .collect::<String>();
        assert!(expected_line.starts_with("ROW_"));

        // Select "ROW_XX_ALPHA" (cols 0..12) on visible row 5
        let target_abs = tab.vis_row_to_abs(target_vis_row);
        tab.selection = Some(TerminalSelection {
            start: TerminalPos {
                abs_row: target_abs,
                col: 0,
            },
            end: TerminalPos {
                abs_row: target_abs,
                col: 12,
            },
            is_alt: false,
        });
        assert!(tab.is_cell_selected_visible(5, 0));
        assert!(!tab.is_cell_selected_visible(4, 0));
        assert_eq!(tab.selected_text().as_deref(), Some(expected_line.as_str()));

        // Scroll UP 3 lines: the text moves DOWN from visible row 5 to visible row 8!
        tab.scroll_lines(3);
        assert_eq!(tab.scrollback_offset(), 3);
        assert!(
            !tab.is_cell_selected_visible(5, 0),
            "selection must NOT float at old viewport row 5 after scrolling"
        );
        assert!(
            tab.is_cell_selected_visible(8, 0),
            "selection must move down to visible row 8 with its text"
        );
        assert!(tab.is_cell_selected_visible(8, 11));
        assert!(!tab.is_cell_selected_visible(8, 12));
        assert_eq!(tab.selected_text().as_deref(), Some(expected_line.as_str()));
        assert_eq!(tab.scrollback_offset(), 3);

        // Scroll UP 20 more lines so the selected text is completely OFF-SCREEN below viewport
        tab.scroll_lines(20);
        assert_eq!(tab.scrollback_offset(), 23);
        for r in 0..10 {
            assert!(
                !tab.is_cell_selected_visible(r, 0),
                "no visible row should be highlighted when selected text scrolled off-screen"
            );
        }
        // Copying while scrolled off-screen must still extract the exact text and restore offset!
        assert!(tab.has_selection());
        assert_eq!(tab.selected_text().as_deref(), Some(expected_line.as_str()));
        assert_eq!(tab.scrollback_offset(), 23);

        // Scroll back down to bottom: selection reappears on visible row 5!
        tab.scroll_to_bottom();
        assert_eq!(tab.scrollback_offset(), 0);
        assert!(tab.is_cell_selected_visible(5, 0));
        assert!(!tab.is_cell_selected_visible(8, 0));
    }

    #[test]
    fn selection_tracks_live_output_and_eviction_cleanly() {
        let mut tab = TerminalTab::connecting(
            "t-live-shift".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        assert!(tab.resize(80, 10));
        tab.feed_bytes(b"\x1b[2J\x1b[H");
        for i in 0..15 {
            tab.feed_bytes(format!("MSG_{i:02}\r\n").as_bytes());
        }

        // Select "MSG_12" on visible row 6
        let vis_row = (0..10)
            .find(|&r| {
                (0..6)
                    .filter_map(|c| tab.parser.screen().cell(r, c))
                    .map(|c| c.contents())
                    .collect::<String>()
                    == "MSG_12"
            })
            .expect("MSG_12 should be visible");
        tab.select_word_at(vis_row, 2);
        assert_eq!(tab.selected_text().as_deref(), Some("MSG_12"));

        // Feed 3 more lines of live output -> MSG_12 shifts UP by 3 rows!
        for i in 15..18 {
            tab.feed_bytes(format!("MSG_{i:02}\r\n").as_bytes());
        }
        assert!(
            !tab.is_cell_selected_visible(vis_row, 2),
            "selection must shift up with text when new output arrives"
        );
        assert!(tab.is_cell_selected_visible(vis_row - 3, 2));
        assert_eq!(tab.selected_text().as_deref(), Some("MSG_12"));

        // Flood past TERM_SCROLLBACK_LEN so MSG_12 is evicted from history
        for i in 0..(TERM_SCROLLBACK_LEN + 50) {
            tab.feed_bytes(format!("FLOOD_{i}\r\n").as_bytes());
        }
        assert!(
            !tab.has_selection(),
            "evicted selection must be cleared cleanly"
        );
        assert!(tab.selected_text().is_none());
    }

    #[test]
    fn multiscreen_scrollback_selection_and_wrapped_lines() {
        let mut tab = TerminalTab::connecting(
            "t-multiscreen".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        assert!(tab.resize(30, 8));
        tab.feed_bytes(b"\x1b[2J\x1b[H");
        for i in 0..30 {
            tab.feed_bytes(format!("LINE_{i:02}\r\n").as_bytes());
        }

        // Select across 20 lines (spanning > 2 viewports of height 8!)
        let start_abs = tab.min_abs_row() + 3;
        let end_abs = start_abs + 19;
        tab.scroll_lines(5);
        tab.selection = Some(TerminalSelection {
            start: TerminalPos {
                abs_row: start_abs,
                col: 0,
            },
            end: TerminalPos {
                abs_row: end_abs,
                col: 7,
            },
            is_alt: false,
        });
        let text = tab.selected_text().expect("expected 20-line selection");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 20);
        assert_eq!(lines[0], "LINE_03");
        assert_eq!(lines[19], "LINE_22");
        assert_eq!(tab.scrollback_offset(), 5);

        // Soft-wrapped line (45 chars in 30-col terminal) copies without spurious newline
        tab.scroll_to_bottom();
        tab.feed_bytes(b"\x1b[2J\x1b[H");
        let long_token = "https://example.com/abcdefghijklmnopqrstuvwxyz";
        tab.feed_bytes(long_token.as_bytes());
        tab.select_line(0);
        assert_eq!(tab.selected_text().as_deref(), Some(long_token));

        // Entering alternate screen clears normal-screen selection
        tab.feed_bytes(b"\x1b[?1049hALT_CONTENT");
        assert!(!tab.has_selection());
    }

    #[test]
    fn wide_characters_and_delimiters_select_cleanly() {
        let mut tab = TerminalTab::connecting(
            "t-wide".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        assert!(tab.resize(60, 10));
        tab.feed_bytes("\x1b[2J\x1b[H(\"hello\") 日本語 ok".as_bytes());

        // Double-click inside ("hello") selects hello without surrounding quotes/parens
        tab.select_word_at(0, 3);
        assert_eq!(tab.selected_text().as_deref(), Some("hello"));

        // Selecting across wide CJK chars does not insert spurious spaces
        let base = tab.visible_base_abs_row();
        tab.selection = Some(TerminalSelection {
            start: TerminalPos {
                abs_row: base,
                col: 10,
            },
            end: TerminalPos {
                abs_row: base,
                col: 19,
            },
            is_alt: false,
        });
        assert_eq!(tab.selected_text().as_deref(), Some("日本語 ok"));
    }

    #[test]
    fn mouse_drag_with_scroll_and_shift_extend_behaves_like_powershell() {
        let mut tab = TerminalTab::connecting(
            "t-drag-scroll".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        assert!(tab.resize(60, 10));
        let font_size = 13.0;
        let lh = terminal_line_height(font_size);
        let cw = 8.0_f32;
        *tab.cell_width.lock().unwrap() = cw;
        *tab.screen_bounds.lock().unwrap() = Some(Bounds::new(
            gpui::point(px(100.0), px(50.0)),
            gpui::size(px(60.0 * cw), px(10.0 * lh)),
        ));

        tab.feed_bytes(b"\x1b[2J\x1b[H");
        for i in 0..30 {
            tab.feed_bytes(format!("ITEM_{i:02} value\r\n").as_bytes());
        }

        // Plain click without dragging should clear on mouse-up (no stuck 1-cell selection)
        let click_pt = gpui::point(px(100.0 + 2.0 * cw + 1.0), px(50.0 + 4.0 * lh + 2.0));
        tab.begin_char_selection(click_pt, font_size, false);
        assert!(!tab.has_selection());
        assert!(tab.finish_selection());
        assert!(tab.selection.is_none());

        // Drag across a single character ('I' at col 0 on row 4) from left edge to right edge
        let row4_y = 50.0 + 4.0 * lh + 3.0;
        tab.begin_char_selection(gpui::point(px(100.0 + 0.1 * cw), px(row4_y)), font_size, false);
        tab.update_selection_drag(gpui::point(px(100.0 + 0.8 * cw), px(row4_y)), font_size);
        tab.finish_selection();
        assert_eq!(tab.selected_text().as_deref(), Some("I"));

        // Start drag at row 8 col 7 ("ITEM_XX" end), scroll UP 12 lines while still holding mouse,
        // and drag to row 2 col 0 -> selection must span across scrollback!
        let row8_y = 50.0 + 8.0 * lh + 3.0;
        let row2_y = 50.0 + 2.0 * lh + 3.0;
        let start_line_label = (0..7)
            .filter_map(|c| tab.parser.screen().cell(8, c))
            .map(|c| c.contents())
            .collect::<String>();
        tab.begin_char_selection(gpui::point(px(100.0 + 7.0 * cw), px(row8_y)), font_size, false);
        tab.scroll_lines(12);
        let end_line_label = (0..7)
            .filter_map(|c| tab.parser.screen().cell(2, c))
            .map(|c| c.contents())
            .collect::<String>();
        let drag_pt = gpui::point(px(100.0 + 0.1 * cw), px(row2_y));
        tab.update_selection_drag(drag_pt, font_size);
        tab.finish_selection();

        let copied = tab.selected_text().expect("expected cross-scrollback drag text");
        let lines: Vec<&str> = copied.lines().collect();
        assert_eq!(lines.len(), 19); // (8 - 2) + 12 + 1 = 19 rows
        assert_eq!(lines[0], format!("{end_line_label} value"));
        assert_eq!(lines[18], start_line_label);

        // Shift+Click after scrolling extends from the original buffer-anchored start
        tab.scroll_lines(2);
        tab.begin_char_selection(gpui::point(px(100.0 + 0.1 * cw), px(row2_y)), font_size, true);
        tab.finish_selection();
        let extended = tab.selected_text().expect("expected shift-extended selection");
        assert_eq!(extended.lines().count(), 21);

        // CSI 3 J (clear scrollback) evicts scrollback rows while preserving live screen rows
        tab.scroll_to_bottom();
        tab.select_word_at(8, 1);
        let live_word = tab.selected_text().expect("live word");
        tab.feed_bytes(b"\x1b[3J");
        assert_eq!(tab.selected_text().as_deref(), Some(live_word.as_str()));

        // ESC c (full RIS terminal reset) clears selection cleanly
        tab.feed_bytes(b"\x1bc");
        assert!(!tab.has_selection());
    }

    #[test]
    fn detects_url_and_trims_trailing_punctuation() {
        let mut tab = TerminalTab::connecting(
            "t2".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        tab.feed_bytes(b"\x1b[2J\x1b[HDocs at (https://example.com/path?a=1). Done");
        let found = tab.url_at(0, 15).expect("expected URL at col 15");
        assert_eq!(found.url, "https://example.com/path?a=1");
        assert!(tab.url_at(0, 2).is_none());
    }

    #[test]
    fn detects_multiline_wrapped_oauth_url() {
        let mut tab = TerminalTab::connecting(
            "t3".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        tab.feed_bytes(
            b"\x1b[2J\x1b[HOpen URL:\r\nhttps://accounts.google.com/o/oauth2/auth?client_id=123\r\n456&scope=openid&state=xyz\r\n\r\nDone",
        );
        // Hovering row 2 (continuation line!) must return the complete joined URL across rows 1 and 2
        let found = tab.url_at(2, 5).expect("expected wrapped URL on row 2");
        assert_eq!(
            found.url,
            "https://accounts.google.com/o/oauth2/auth?client_id=123456&scope=openid&state=xyz"
        );
        assert_eq!(found.spans.len(), 2);
    }

    #[test]
    fn detects_osc8_hyperlink() {
        let mut tab = TerminalTab::connecting(
            "t4".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        tab.feed_bytes(
            b"\x1b[2J\x1b[H\x1b]8;;https://accounts.google.com/auth\x07Click here to authenticate\x1b]8;;\x07",
        );
        let found = tab.url_at(0, 6).expect("expected OSC 8 hyperlink");
        assert_eq!(found.url, "https://accounts.google.com/auth");
    }

    #[test]
    fn resizing_to_smaller_height_keeps_bottom_prompt_visible_and_scrollable() {
        let mut tab = TerminalTab::connecting(
            "t5".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        tab.feed_bytes(b"\x1b[2J\x1b[H");
        for i in 1..=50 {
            tab.feed_bytes(format!("line {i:02}\r\n").as_bytes());
        }
        tab.feed_bytes(b"BOTTOM_PROMPT> ");

        // Shrink viewport to 16 rows (like a shorter desktop window)
        assert!(tab.resize(100, 16));
        assert_eq!(tab.rows, 16);
        assert_eq!(tab.cols, 100);
        assert_eq!(tab.scrollback_offset(), 0);

        let screen_contents = tab.parser.screen().contents();
        assert!(
            screen_contents.contains("BOTTOM_PROMPT>"),
            "bottom prompt must remain visible after shrinking height: {screen_contents}"
        );

        // Scroll up into history, then scroll all the way back down to bottom
        tab.scroll_lines(20);
        assert!(tab.scrollback_offset() > 0);
        assert!(!tab.parser.screen().contents().contains("BOTTOM_PROMPT>"));

        tab.scroll_lines(-100);
        assert_eq!(tab.scrollback_offset(), 0);
        assert!(tab.parser.screen().contents().contains("BOTTOM_PROMPT>"));
    }

    #[test]
    fn narrowing_then_widening_reflows_without_deleting_text() {
        let mut tab = TerminalTab::connecting(
            "t6".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        tab.feed_bytes(b"\x1b[2J\x1b[H");
        tab.feed_bytes(
            b"Resume with -c (or continue with --conversation=full-id-1234567890)\r\n\
              \x1b[32mGot it - leaving 927 MB reaper, 12h Chromium timer already active.\x1b[0m\r\n\
              root@orangepi-server:~# ",
        );

        // Shrink width way down (24 cols) then expand back to 112 cols, multiple times
        assert!(tab.resize(24, 34));
        assert!(tab.resize(50, 34));
        assert!(tab.resize(20, 34));
        assert!(tab.resize(112, 34));

        let contents = tab.parser.screen().contents();
        assert!(
            contents.contains("Resume with -c (or continue with --conversation=full-id-1234567890)"),
            "expected full first line preserved after narrow->wide reflow, got:\n{contents}"
        );
        assert!(
            contents.contains("Got it - leaving 927 MB reaper, 12h Chromium timer already active."),
            "expected full second line preserved after narrow->wide reflow, got:\n{contents}"
        );
        assert!(
            contents.contains("root@orangepi-server:~#"),
            "expected prompt preserved, got:\n{contents}"
        );
        // Verify green foreground color was preserved on row 1
        assert_eq!(
            tab.parser.screen().cell(1, 0).map(|c| c.fgcolor()),
            Some(vt100::Color::Idx(2))
        );
        // Verify cursor stayed right after the prompt space
        assert_eq!(tab.parser.screen().cursor_position(), (2, 24));
    }

    #[test]
    fn reflow_preserves_exact_width_lines_and_alternate_screen() {
        let mut tab = TerminalTab::connecting(
            "t7".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        tab.feed_bytes(b"\x1b[2J\x1b[H");
        let exact_40 = "X".repeat(40);
        tab.feed_bytes(format!("{exact_40}\r\nSECOND_LINE").as_bytes());

        assert!(tab.resize(40, 20));
        let contents = tab.parser.screen().contents();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines, vec![exact_40.as_str(), "SECOND_LINE"]);

        // Entering alternate screen should stay in alternate screen on resize
        tab.feed_bytes(b"\x1b[?1049hALT_VIEW");
        assert!(tab.parser.screen().alternate_screen());
        assert!(tab.resize(60, 20));
        assert!(tab.parser.screen().alternate_screen());
    }

    #[test]
    fn terminal_search_matches_cycles_and_clears() {
        let mut tab = TerminalTab::connecting(
            "t-search".into(),
            None,
            "srv".into(),
            "127.0.0.1".into(),
            22,
            "root".into(),
        );
        tab.feed_bytes(b"\x1b[2J\x1b[Halpha beta\r\nBETA gamma\r\ndelta beta");
        tab.update_search("beta");
        assert_eq!(tab.search_matches.len(), 3);
        assert_eq!(tab.active_match_idx, 2);
        tab.next_search_match();
        assert_eq!(tab.active_match_idx, 0);
        tab.prev_search_match();
        assert_eq!(tab.active_match_idx, 2);
        tab.prev_search_match();
        assert_eq!(tab.active_match_idx, 1);

        tab.clear_buffer();
        assert!(tab.search_matches.is_empty());
        assert!(tab.recent_output_tail.is_empty());
    }

    #[test]
    fn strip_ansi_removes_csi_and_osc_for_transcripts() {
        let raw = b"\x1b[32mhello\x1b[0m \x1b]0;window title\x07world\r\n\x1b[1;31merr\x1b[0m\n";
        let clean = strip_ansi_for_log(raw);
        assert_eq!(clean, "hello world\nerr\n");
    }
}
