use std::ops::Range;
use std::time::{Duration, Instant};

use gpui::{
    div, ease_out_quint, fill, point, prelude::*, px, relative, size, Animation,
    AnimationExt as _, App, Bounds, ClipboardItem, ContentMask, Context, Corners, CursorStyle,
    DispatchPhase, Element, ElementId, ElementInputHandler, Entity, EntityInputHandler,
    EventEmitter, FocusHandle, Focusable, GlobalElementId, KeyDownEvent, LayoutId, MouseButton,
    MouseDownEvent, MouseMoveEvent, MouseUpEvent, PaintQuad, Pixels, Point, ScrollWheelEvent,
    ShapedLine, SharedString, Style, Task, TextRun, UTF16Selection, UnderlineStyle, WeakEntity,
    Window,
};

use crate::theme::{AccentPreset, ThemeMode, ThemePalette, UiSettings};

const MAX_UNDO_HISTORY: usize = 128;
const UNDO_COALESCE_MS: u64 = 750;
const CARET_BLINK_MS: u64 = 530;
const MASK_CHAR: char = '•';

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub enum TextFieldEvent {
    Changed(String),
    Submit(String),
    Cancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CharClass {
    Word,
    Whitespace,
    Newline,
    Punct,
}

fn char_class(c: char) -> CharClass {
    if c == '\n' || c == '\r' {
        CharClass::Newline
    } else if c == ' ' || c == '\t' {
        CharClass::Whitespace
    } else if c.is_alphanumeric() || c == '_' {
        CharClass::Word
    } else {
        CharClass::Punct
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SelectionMode {
    Char,
    Word(Range<usize>),
    Line(Range<usize>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EditSnapshot {
    value: String,
    selected_range: Range<usize>,
    selection_reversed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LastEditKind {
    None,
    Insert,
    Delete,
}

struct ShapedLineEntry {
    /// Byte range within `TextField::value` (excluding trailing `\n`).
    range: Range<usize>,
    shaped: ShapedLine,
}

fn clamp_char_boundary(s: &str, pos: usize) -> usize {
    let mut idx = pos.min(s.len());
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn prev_char_boundary_in(s: &str, pos: usize) -> usize {
    let pos = clamp_char_boundary(s, pos);
    if pos == 0 {
        return 0;
    }
    let mut idx = pos - 1;
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn next_char_boundary_in(s: &str, pos: usize) -> usize {
    let pos = clamp_char_boundary(s, pos);
    if pos >= s.len() {
        return s.len();
    }
    let mut idx = pos + 1;
    while idx < s.len() && !s.is_char_boundary(idx) {
        idx += 1;
    }
    idx
}

fn offset_from_utf16_in(s: &str, utf16_offset: usize) -> usize {
    let mut utf8_count = 0;
    let mut u16_count = 0;
    for ch in s.chars() {
        if u16_count >= utf16_offset {
            break;
        }
        u16_count += ch.len_utf16();
        utf8_count += ch.len_utf8();
    }
    utf8_count
}

fn offset_to_utf16_in(s: &str, utf8_offset: usize) -> usize {
    let target = clamp_char_boundary(s, utf8_offset);
    let mut u16_count = 0;
    let mut utf8_count = 0;
    for ch in s.chars() {
        if utf8_count >= target {
            break;
        }
        utf8_count += ch.len_utf8();
        u16_count += ch.len_utf16();
    }
    u16_count
}

fn line_ranges(value: &str, multiline: bool) -> Vec<Range<usize>> {
    if !multiline {
        return std::iter::once(0..value.len()).collect();
    }
    let mut out = Vec::new();
    let mut start = 0;
    for (idx, b) in value.bytes().enumerate() {
        if b == b'\n' {
            out.push(start..idx);
            start = idx + 1;
        }
    }
    out.push(start..value.len());
    out
}

fn line_value_to_display(line_text: &str, masked: bool, local_val_idx: usize) -> usize {
    let safe = clamp_char_boundary(line_text, local_val_idx);
    if masked {
        line_text[..safe].chars().count() * MASK_CHAR.len_utf8()
    } else {
        safe
    }
}

fn line_display_to_value(line_text: &str, masked: bool, local_disp_idx: usize) -> usize {
    if !masked {
        return clamp_char_boundary(line_text, local_disp_idx);
    }
    let char_idx = local_disp_idx / MASK_CHAR.len_utf8();
    line_text
        .char_indices()
        .nth(char_idx)
        .map(|(byte_idx, _)| byte_idx)
        .unwrap_or(line_text.len())
}

fn line_bounds_for_offset(value: &str, multiline: bool, pos: usize) -> Range<usize> {
    if !multiline {
        return 0..value.len();
    }
    let pos = clamp_char_boundary(value, pos);
    let start = value[..pos].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let end = value[pos..]
        .find('\n')
        .map(|rel| pos + rel)
        .unwrap_or(value.len());
    start..end
}

fn word_range_at(value: &str, masked: bool, pos: usize) -> Range<usize> {
    if value.is_empty() {
        return 0..0;
    }
    if masked {
        return 0..value.len();
    }
    let mut idx = clamp_char_boundary(value, pos);
    if idx >= value.len() {
        idx = prev_char_boundary_in(value, value.len());
    }
    let Some(mut ch) = value[idx..].chars().next() else {
        return value.len()..value.len();
    };
    // If clicked directly on a newline (e.g. past end of a line in multiline),
    // select the last token on that line if non-empty.
    if char_class(ch) == CharClass::Newline {
        if idx > 0 {
            let prev = prev_char_boundary_in(value, idx);
            if let Some(prev_ch) = value[prev..].chars().next() {
                if char_class(prev_ch) != CharClass::Newline {
                    idx = prev;
                    ch = prev_ch;
                } else {
                    return idx..idx;
                }
            }
        } else {
            return 0..0;
        }
    }

    let cls = char_class(ch);
    let mut start = idx;
    while start > 0 {
        let prev = prev_char_boundary_in(value, start);
        let Some(prev_ch) = value[prev..].chars().next() else {
            break;
        };
        if char_class(prev_ch) == cls {
            start = prev;
        } else {
            break;
        }
    }

    let mut end = next_char_boundary_in(value, idx);
    while end < value.len() {
        let Some(next_ch) = value[end..].chars().next() else {
            break;
        };
        if char_class(next_ch) == cls {
            end = next_char_boundary_in(value, end);
        } else {
            break;
        }
    }

    start..end
}

fn prev_word_boundary_in(value: &str, masked: bool, pos: usize) -> usize {
    let mut idx = clamp_char_boundary(value, pos);
    if idx == 0 {
        return 0;
    }
    if masked {
        return 0;
    }

    let mut skipped_ws = false;
    while idx > 0 {
        let prev = prev_char_boundary_in(value, idx);
        let Some(ch) = value[prev..].chars().next() else {
            break;
        };
        if char_class(ch) == CharClass::Whitespace {
            idx = prev;
            skipped_ws = true;
        } else {
            break;
        }
    }
    if idx == 0 {
        return 0;
    }

    let prev = prev_char_boundary_in(value, idx);
    let Some(ch) = value[prev..].chars().next() else {
        return 0;
    };
    let cls = char_class(ch);
    if cls == CharClass::Newline {
        return if skipped_ws { idx } else { prev };
    }

    idx = prev;
    while idx > 0 {
        let p = prev_char_boundary_in(value, idx);
        let Some(c) = value[p..].chars().next() else {
            break;
        };
        if char_class(c) == cls {
            idx = p;
        } else {
            break;
        }
    }
    idx
}

fn next_word_boundary_in(value: &str, masked: bool, pos: usize) -> usize {
    let len = value.len();
    let mut idx = clamp_char_boundary(value, pos);
    if idx >= len {
        return len;
    }
    if masked {
        return len;
    }

    let mut skipped_ws = false;
    while idx < len {
        let Some(ch) = value[idx..].chars().next() else {
            break;
        };
        if char_class(ch) == CharClass::Whitespace {
            idx = next_char_boundary_in(value, idx);
            skipped_ws = true;
        } else {
            break;
        }
    }
    if idx >= len {
        return len;
    }

    let Some(ch) = value[idx..].chars().next() else {
        return len;
    };
    let cls = char_class(ch);
    if cls == CharClass::Newline {
        return if skipped_ws {
            idx
        } else {
            next_char_boundary_in(value, idx)
        };
    }

    idx = next_char_boundary_in(value, idx);
    while idx < len {
        let Some(c) = value[idx..].chars().next() else {
            break;
        };
        if char_class(c) == cls {
            idx = next_char_boundary_in(value, idx);
        } else {
            break;
        }
    }
    idx
}

fn hit_test_line_x(
    line_text: &str,
    shaped: &ShapedLine,
    masked: bool,
    rel_x: Pixels,
    for_word_hit: bool,
) -> usize {
    if line_text.is_empty() {
        return 0;
    }
    if rel_x <= px(0.0) {
        return 0;
    }

    if for_word_hit {
        if let Some(disp_idx) = shaped.index_for_x(rel_x) {
            return line_display_to_value(line_text, masked, disp_idx);
        }
        return line_text.len();
    }

    if rel_x >= shaped.width {
        return line_text.len();
    }

    let mut disp_idx = shaped.closest_index_for_x(rel_x);
    // GPUI's closest_index_for_x falls through to `shaped.len` for the entire last glyph
    // when len > 1; compare against the midpoint of the final character so clicking the left
    // half of the last character places the cursor before it.
    if disp_idx >= shaped.len && shaped.len > 0 {
        let last_start = if masked {
            shaped.len.saturating_sub(MASK_CHAR.len_utf8())
        } else {
            prev_char_boundary_in(line_text, line_text.len())
        };
        let last_x = shaped.x_for_index(last_start);
        if rel_x < (last_x + shaped.width) * 0.5 {
            disp_idx = last_start;
        }
    }

    line_display_to_value(line_text, masked, disp_idx)
}

/// Reusable HTML5-grade interactive GPUI text input supporting:
/// - Click-to-position cursor, drag-to-select (including outside bounds & auto-scroll)
/// - Double-click/tap to select word (plus double-click+drag word selection)
/// - Triple-click to select all (single-line) or line (multiline, plus line-drag)
/// - Shift+Click selection extension
/// - Full keyboard navigation & selection: Arrows, Shift+Arrows, Ctrl/Alt+Arrows (word),
///   Home/End, Ctrl+Home/End, Up/Down/PageUp/PageDown (with preserved column goal_x)
/// - Clipboard & editing: Ctrl+A/C/X/V, Shift+Insert/Ctrl+Insert/Shift+Delete,
///   Ctrl+Backspace/Delete (word delete), Ctrl+U, Ctrl+Z / Ctrl+Y / Ctrl+Shift+Z (undo/redo)
/// - Native OS IME / dead-key / emoji picker composition via `EntityInputHandler`
/// - Horizontal scrolling (single-line) and vertical + horizontal scrolling (multiline)
/// - Crisp blinking caret, selection highlight, and masked password field semantics
pub struct TextField {
    focus_handle: FocusHandle,
    value: String,
    selected_range: Range<usize>,
    selection_reversed: bool,
    marked_range: Option<Range<usize>>,
    placeholder: SharedString,
    masked: bool,
    multiline: bool,
    monospace: bool,
    compact: bool,
    theme_mode: ThemeMode,
    accent: AccentPreset,

    is_selecting: bool,
    selection_mode: SelectionMode,

    scroll_x: Pixels,
    scroll_y: Pixels,
    ensure_cursor_visible: bool,
    goal_x: Option<Pixels>,

    last_lines: Vec<ShapedLineEntry>,
    last_bounds: Option<Bounds<Pixels>>,
    last_line_height: Pixels,

    undo_stack: Vec<EditSnapshot>,
    redo_stack: Vec<EditSnapshot>,
    last_edit_kind: LastEditKind,
    last_edit_at: Option<Instant>,

    caret_visible: bool,
    blink_task: Option<Task<()>>,
    was_focused: bool,
    focus_epoch: u64,
}

impl EventEmitter<TextFieldEvent> for TextField {}

impl Focusable for TextField {
    fn focus_handle(&self, _cx: &App) -> FocusHandle {
        self.focus_handle.clone()
    }
}

impl TextField {
    pub fn new(placeholder: impl Into<SharedString>, cx: &mut Context<Self>) -> Self {
        Self {
            focus_handle: cx.focus_handle(),
            value: String::new(),
            selected_range: 0..0,
            selection_reversed: false,
            marked_range: None,
            placeholder: placeholder.into(),
            masked: false,
            multiline: false,
            monospace: false,
            compact: false,
            theme_mode: ThemeMode::Light,
            accent: AccentPreset::Blue,
            is_selecting: false,
            selection_mode: SelectionMode::Char,
            scroll_x: px(0.0),
            scroll_y: px(0.0),
            ensure_cursor_visible: false,
            goal_x: None,
            last_lines: Vec::new(),
            last_bounds: None,
            last_line_height: px(16.0),
            undo_stack: Vec::new(),
            redo_stack: Vec::new(),
            last_edit_kind: LastEditKind::None,
            last_edit_at: None,
            caret_visible: true,
            blink_task: None,
            was_focused: false,
            focus_epoch: 0,
        }
    }

    pub fn with_masked(mut self, masked: bool) -> Self {
        self.masked = masked;
        self
    }

    pub fn with_multiline(mut self, multiline: bool) -> Self {
        self.multiline = multiline;
        self
    }

    pub fn with_monospace(mut self, monospace: bool) -> Self {
        self.monospace = monospace;
        self
    }

    pub fn with_compact(mut self, compact: bool) -> Self {
        self.compact = compact;
        self
    }

    pub fn with_value(mut self, val: impl Into<String>) -> Self {
        let s = self.sanitize_text(&val.into());
        let len = s.len();
        self.value = s;
        self.selected_range = len..len;
        self.selection_reversed = false;
        self.marked_range = None;
        self
    }

    pub fn set_appearance(&mut self, mode: ThemeMode, accent: AccentPreset) {
        self.theme_mode = mode;
        self.accent = accent;
    }

    pub fn value(&self) -> &str {
        &self.value
    }

    pub fn set_value(&mut self, val: impl Into<String>, cx: &mut Context<Self>) {
        self.value = self.sanitize_text(&val.into());
        let len = self.value.len();
        self.selected_range = len..len;
        self.selection_reversed = false;
        self.marked_range = None;
        self.is_selecting = false;
        self.scroll_x = px(0.0);
        self.scroll_y = px(0.0);
        self.goal_x = None;
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.last_edit_kind = LastEditKind::None;
        self.last_edit_at = None;
        self.ensure_cursor_visible = true;
        self.reset_blink(cx);
        cx.notify();
    }

    pub fn clear(&mut self, cx: &mut Context<Self>) {
        self.value.clear();
        self.selected_range = 0..0;
        self.selection_reversed = false;
        self.marked_range = None;
        self.is_selecting = false;
        self.scroll_x = px(0.0);
        self.scroll_y = px(0.0);
        self.goal_x = None;
        self.undo_stack.clear();
        self.redo_stack.clear();
        self.last_edit_kind = LastEditKind::None;
        self.last_edit_at = None;
        self.ensure_cursor_visible = true;
        self.reset_blink(cx);
        cx.notify();
    }

    fn sanitize_text(&self, text: &str) -> String {
        if self.multiline {
            text.replace("\r\n", "\n").replace('\r', "\n")
        } else {
            text.replace(['\r', '\n'], "")
        }
    }

    fn cursor_offset(&self) -> usize {
        let raw = if self.selection_reversed {
            self.selected_range.start
        } else {
            self.selected_range.end
        };
        clamp_char_boundary(&self.value, raw)
    }

    fn anchor_offset(&self) -> usize {
        let raw = if self.selection_reversed {
            self.selected_range.end
        } else {
            self.selected_range.start
        };
        clamp_char_boundary(&self.value, raw)
    }

    fn clamped_selection(&self) -> Range<usize> {
        let start = clamp_char_boundary(&self.value, self.selected_range.start);
        let end = clamp_char_boundary(&self.value, self.selected_range.end);
        if start <= end {
            start..end
        } else {
            end..start
        }
    }

    fn reset_blink(&mut self, cx: &mut Context<Self>) {
        self.caret_visible = true;
        if !self.was_focused {
            return;
        }
        self.start_blink_loop(cx);
    }

    fn start_blink_loop(&mut self, cx: &mut Context<Self>) {
        self.caret_visible = true;
        self.blink_task = Some(cx.spawn(async move |this: WeakEntity<Self>, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(CARET_BLINK_MS))
                    .await;
                let keep_going = this
                    .update(cx, |field, cx| {
                        if !field.was_focused {
                            return false;
                        }
                        if field.selected_range.is_empty() {
                            field.caret_visible = !field.caret_visible;
                            cx.notify();
                        }
                        true
                    })
                    .unwrap_or(false);
                if !keep_going {
                    break;
                }
            }
        }));
    }

    fn stop_blink_loop(&mut self) {
        self.blink_task = None;
        self.caret_visible = true;
    }

    fn move_to(&mut self, offset: usize, cx: &mut Context<Self>) {
        let pos = clamp_char_boundary(&self.value, offset);
        self.selected_range = pos..pos;
        self.selection_reversed = false;
        self.marked_range = None;
        self.goal_x = None;
        self.ensure_cursor_visible = true;
        self.last_edit_kind = LastEditKind::None;
        self.reset_blink(cx);
        cx.notify();
    }

    fn select_to(&mut self, offset: usize, cx: &mut Context<Self>) {
        let pos = clamp_char_boundary(&self.value, offset);
        let anchor = self.anchor_offset();
        if pos < anchor {
            self.selected_range = pos..anchor;
            self.selection_reversed = true;
        } else {
            self.selected_range = anchor..pos;
            self.selection_reversed = false;
        }
        self.marked_range = None;
        self.ensure_cursor_visible = true;
        self.last_edit_kind = LastEditKind::None;
        self.reset_blink(cx);
        cx.notify();
    }

    fn set_selection(&mut self, range: Range<usize>, reversed: bool, cx: &mut Context<Self>) {
        let start = clamp_char_boundary(&self.value, range.start);
        let end = clamp_char_boundary(&self.value, range.end);
        self.selected_range = if start <= end {
            start..end
        } else {
            end..start
        };
        self.selection_reversed = reversed && !self.selected_range.is_empty();
        self.marked_range = None;
        self.ensure_cursor_visible = true;
        self.last_edit_kind = LastEditKind::None;
        self.reset_blink(cx);
        cx.notify();
    }

    fn select_all(&mut self, cx: &mut Context<Self>) {
        self.set_selection(0..self.value.len(), false, cx);
    }

    fn push_undo_if_needed(&mut self, kind: LastEditKind, can_coalesce: bool) {
        let now = Instant::now();
        let coalesce = can_coalesce
            && kind != LastEditKind::None
            && self.last_edit_kind == kind
            && self
                .last_edit_at
                .map(|t| now.duration_since(t) <= Duration::from_millis(UNDO_COALESCE_MS))
                .unwrap_or(false)
            && !self.undo_stack.is_empty();

        if !coalesce {
            let snap = EditSnapshot {
                value: self.value.clone(),
                selected_range: self.clamped_selection(),
                selection_reversed: self.selection_reversed,
            };
            if self.undo_stack.last() != Some(&snap) {
                self.undo_stack.push(snap);
                if self.undo_stack.len() > MAX_UNDO_HISTORY {
                    self.undo_stack.remove(0);
                }
            }
        }
        self.redo_stack.clear();
        self.last_edit_kind = kind;
        self.last_edit_at = Some(now);
    }

    fn apply_edit(
        &mut self,
        range: Range<usize>,
        replacement: &str,
        kind: LastEditKind,
        can_coalesce: bool,
        cx: &mut Context<Self>,
    ) {
        let start = clamp_char_boundary(&self.value, range.start);
        let end = clamp_char_boundary(&self.value, range.end).max(start);
        let clean = self.sanitize_text(replacement);

        if start == end && clean.is_empty() && self.marked_range.is_none() {
            return;
        }

        self.push_undo_if_needed(kind, can_coalesce);
        self.value.replace_range(start..end, &clean);
        let new_cursor = start + clean.len();
        self.selected_range = new_cursor..new_cursor;
        self.selection_reversed = false;
        self.marked_range = None;
        self.goal_x = None;
        self.ensure_cursor_visible = true;
        self.reset_blink(cx);
        cx.emit(TextFieldEvent::Changed(self.value.clone()));
        cx.notify();
    }

    fn undo(&mut self, cx: &mut Context<Self>) {
        let Some(prev) = self.undo_stack.pop() else {
            return;
        };
        let current = EditSnapshot {
            value: self.value.clone(),
            selected_range: self.clamped_selection(),
            selection_reversed: self.selection_reversed,
        };
        self.redo_stack.push(current);
        self.value = prev.value;
        self.selected_range = prev.selected_range;
        self.selection_reversed = prev.selection_reversed;
        self.marked_range = None;
        self.goal_x = None;
        self.last_edit_kind = LastEditKind::None;
        self.last_edit_at = None;
        self.ensure_cursor_visible = true;
        self.reset_blink(cx);
        cx.emit(TextFieldEvent::Changed(self.value.clone()));
        cx.notify();
    }

    fn redo(&mut self, cx: &mut Context<Self>) {
        let Some(next) = self.redo_stack.pop() else {
            return;
        };
        let current = EditSnapshot {
            value: self.value.clone(),
            selected_range: self.clamped_selection(),
            selection_reversed: self.selection_reversed,
        };
        self.undo_stack.push(current);
        self.value = next.value;
        self.selected_range = next.selected_range;
        self.selection_reversed = next.selection_reversed;
        self.marked_range = None;
        self.goal_x = None;
        self.last_edit_kind = LastEditKind::None;
        self.last_edit_at = None;
        self.ensure_cursor_visible = true;
        self.reset_blink(cx);
        cx.emit(TextFieldEvent::Changed(self.value.clone()));
        cx.notify();
    }

    fn copy_selection(&self, cx: &mut Context<Self>) {
        if self.masked {
            return;
        }
        let sel = self.clamped_selection();
        if !sel.is_empty() {
            cx.write_to_clipboard(ClipboardItem::new_string(self.value[sel].to_string()));
        }
    }

    fn cut_selection(&mut self, cx: &mut Context<Self>) {
        if self.masked {
            return;
        }
        let sel = self.clamped_selection();
        if !sel.is_empty() {
            cx.write_to_clipboard(ClipboardItem::new_string(
                self.value[sel.clone()].to_string(),
            ));
            self.apply_edit(sel, "", LastEditKind::None, false, cx);
        }
    }

    fn paste_clipboard(&mut self, cx: &mut Context<Self>) {
        if let Some(text) = cx.read_from_clipboard().and_then(|item| item.text()) {
            let sel = self.clamped_selection();
            self.apply_edit(sel, &text, LastEditKind::None, false, cx);
        }
    }

    fn delete_backward(&mut self, by_word: bool, cx: &mut Context<Self>) {
        let sel = self.clamped_selection();
        if !sel.is_empty() {
            self.apply_edit(sel, "", LastEditKind::Delete, false, cx);
            return;
        }
        let cursor = sel.start;
        if cursor == 0 {
            return;
        }
        let prev = if by_word {
            prev_word_boundary_in(&self.value, self.masked, cursor)
        } else {
            prev_char_boundary_in(&self.value, cursor)
        };
        let can_coalesce = !by_word;
        self.apply_edit(prev..cursor, "", LastEditKind::Delete, can_coalesce, cx);
    }

    fn delete_forward(&mut self, by_word: bool, cx: &mut Context<Self>) {
        let sel = self.clamped_selection();
        if !sel.is_empty() {
            self.apply_edit(sel, "", LastEditKind::Delete, false, cx);
            return;
        }
        let cursor = sel.end;
        if cursor >= self.value.len() {
            return;
        }
        let next = if by_word {
            next_word_boundary_in(&self.value, self.masked, cursor)
        } else {
            next_char_boundary_in(&self.value, cursor)
        };
        let can_coalesce = !by_word;
        self.apply_edit(cursor..next, "", LastEditKind::Delete, can_coalesce, cx);
    }

    fn index_for_mouse_position(&self, position: Point<Pixels>, for_word_hit: bool) -> usize {
        if self.value.is_empty() {
            return 0;
        }
        let Some(bounds) = self.last_bounds else {
            return self.value.len();
        };
        if self.last_lines.is_empty() {
            return self.value.len();
        }

        let line_idx = if self.multiline {
            let line_h = self.last_line_height.max(px(1.0));
            let rel_y = position.y - bounds.top() + self.scroll_y;
            if rel_y <= px(0.0) {
                0
            } else {
                let raw = (f32::from(rel_y) / f32::from(line_h)).floor() as usize;
                raw.min(self.last_lines.len() - 1)
            }
        } else {
            0
        };

        let entry = &self.last_lines[line_idx];
        let start = clamp_char_boundary(&self.value, entry.range.start);
        let end = clamp_char_boundary(&self.value, entry.range.end).max(start);
        let line_text = &self.value[start..end];
        let rel_x = position.x - bounds.left() + self.scroll_x;
        let local = hit_test_line_x(line_text, &entry.shaped, self.masked, rel_x, for_word_hit);
        (start + local).min(self.value.len())
    }

    fn line_index_for_offset(&self, offset: usize) -> usize {
        let pos = clamp_char_boundary(&self.value, offset);
        for (i, line) in self.last_lines.iter().enumerate() {
            if pos >= line.range.start && pos <= line.range.end {
                return i;
            }
        }
        self.last_lines.len().saturating_sub(1)
    }

    fn x_for_offset_on_line(&self, line_idx: usize, offset: usize) -> Pixels {
        let Some(entry) = self.last_lines.get(line_idx) else {
            return px(0.0);
        };
        let start = clamp_char_boundary(&self.value, entry.range.start);
        let end = clamp_char_boundary(&self.value, entry.range.end).max(start);
        let line_text = &self.value[start..end];
        let local = clamp_char_boundary(&self.value, offset)
            .saturating_sub(start)
            .min(line_text.len());
        let disp_idx = line_value_to_display(line_text, self.masked, local);
        entry.shaped.x_for_index(disp_idx)
    }

    fn move_vertical(&mut self, delta_lines: isize, extend_selection: bool, cx: &mut Context<Self>) {
        if !self.multiline {
            let target = if delta_lines < 0 { 0 } else { self.value.len() };
            if extend_selection {
                self.select_to(target, cx);
            } else {
                self.move_to(target, cx);
            }
            return;
        }

        if self.last_lines.is_empty() {
            return;
        }

        let cursor = if !extend_selection && !self.selected_range.is_empty() {
            if delta_lines < 0 {
                self.selected_range.start
            } else {
                self.selected_range.end
            }
        } else {
            self.cursor_offset()
        };

        let cur_line = self.line_index_for_offset(cursor);
        let target_x = self
            .goal_x
            .unwrap_or_else(|| self.x_for_offset_on_line(cur_line, cursor));
        let max_line = (self.last_lines.len() - 1) as isize;
        let next_line_signed = cur_line as isize + delta_lines;

        let target_offset = if next_line_signed < 0 {
            0
        } else if next_line_signed > max_line {
            self.value.len()
        } else {
            let next_line = next_line_signed as usize;
            let entry = &self.last_lines[next_line];
            let start = clamp_char_boundary(&self.value, entry.range.start);
            let end = clamp_char_boundary(&self.value, entry.range.end).max(start);
            let line_text = &self.value[start..end];
            let local = hit_test_line_x(line_text, &entry.shaped, self.masked, target_x, false);
            (start + local).min(self.value.len())
        };

        if extend_selection {
            self.select_to(target_offset, cx);
        } else {
            self.move_to(target_offset, cx);
        }
        // Preserve goal_x across consecutive vertical moves.
        self.goal_x = Some(target_x);
    }

    fn handle_mouse_down(
        &mut self,
        event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        window.focus(&self.focus_handle);
        cx.stop_propagation();

        self.marked_range = None;
        self.goal_x = None;

        let click_count = event.click_count.max(1);
        match click_count {
            1 => {
                let pos = self.index_for_mouse_position(event.position, false);
                self.is_selecting = true;
                self.selection_mode = SelectionMode::Char;
                if event.modifiers.shift {
                    self.select_to(pos, cx);
                } else {
                    self.move_to(pos, cx);
                }
            }
            2 => {
                let pos = self.index_for_mouse_position(event.position, true);
                let word = word_range_at(&self.value, self.masked, pos);
                self.is_selecting = true;
                self.selection_mode = SelectionMode::Word(word.clone());
                self.set_selection(word, false, cx);
            }
            _ => {
                let range = if self.multiline {
                    let pos = self.index_for_mouse_position(event.position, false);
                    line_bounds_for_offset(&self.value, true, pos)
                } else {
                    0..self.value.len()
                };
                self.is_selecting = true;
                self.selection_mode = SelectionMode::Line(range.clone());
                self.set_selection(range, false, cx);
            }
        }
    }

    fn handle_right_mouse_down(
        &mut self,
        _event: &MouseDownEvent,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        // Right-clicking focuses without clearing any existing selection (HTML5 behavior).
        window.focus(&self.focus_handle);
        cx.stop_propagation();
        cx.notify();
    }

    fn handle_mouse_move(
        &mut self,
        event: &MouseMoveEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.is_selecting {
            return;
        }
        if !event.dragging() {
            self.is_selecting = false;
            return;
        }

        let prev_range = self.selected_range.clone();
        let prev_rev = self.selection_reversed;

        match self.selection_mode.clone() {
            SelectionMode::Char => {
                let pos = self.index_for_mouse_position(event.position, false);
                let anchor = self.anchor_offset();
                if pos < anchor {
                    self.selected_range = pos..anchor;
                    self.selection_reversed = true;
                } else {
                    self.selected_range = anchor..pos;
                    self.selection_reversed = false;
                }
            }
            SelectionMode::Word(anchor_word) => {
                let pos = self.index_for_mouse_position(event.position, true);
                let hover_word = word_range_at(&self.value, self.masked, pos);
                if hover_word.start < anchor_word.start {
                    self.selected_range = hover_word.start..anchor_word.end;
                    self.selection_reversed = true;
                } else if hover_word.end > anchor_word.end {
                    self.selected_range = anchor_word.start..hover_word.end;
                    self.selection_reversed = false;
                } else {
                    self.selected_range = anchor_word;
                    self.selection_reversed = false;
                }
            }
            SelectionMode::Line(anchor_line) => {
                let pos = self.index_for_mouse_position(event.position, false);
                let hover_line = line_bounds_for_offset(&self.value, self.multiline, pos);
                if hover_line.start < anchor_line.start {
                    self.selected_range = hover_line.start..anchor_line.end;
                    self.selection_reversed = true;
                } else if hover_line.end > anchor_line.end {
                    self.selected_range = anchor_line.start..hover_line.end;
                    self.selection_reversed = false;
                } else {
                    self.selected_range = anchor_line;
                    self.selection_reversed = false;
                }
            }
        }

        if self.selected_range != prev_range || self.selection_reversed != prev_rev {
            self.ensure_cursor_visible = true;
            cx.notify();
        }
    }

    fn handle_mouse_up(
        &mut self,
        _event: &MouseUpEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.is_selecting {
            self.is_selecting = false;
            self.reset_blink(cx);
            cx.notify();
        }
    }

    fn handle_scroll_wheel(
        &mut self,
        event: &ScrollWheelEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if !self.multiline {
            return;
        }
        let line_h = self.last_line_height.max(px(16.0));
        let delta = event.delta.pixel_delta(line_h);
        let Some(bounds) = self.last_bounds else {
            return;
        };
        let total_h = line_h * (self.last_lines.len().max(1) as f32);
        let max_y = (total_h - bounds.size.height).max(px(0.0));
        let next_y = (self.scroll_y - delta.y).clamp(px(0.0), max_y);

        let max_line_w = self
            .last_lines
            .iter()
            .map(|l| l.shaped.width)
            .fold(px(0.0), Pixels::max);
        let max_x = (max_line_w + px(8.0) - bounds.size.width).max(px(0.0));
        let next_x = (self.scroll_x - delta.x).clamp(px(0.0), max_x);

        if next_y != self.scroll_y || next_x != self.scroll_x {
            self.scroll_y = next_y;
            self.scroll_x = next_x;
            self.ensure_cursor_visible = false;
            cx.stop_propagation();
            cx.notify();
        }
    }

    fn handle_key_down(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let ks = &event.keystroke;
        // Preserve Windows AltGr (Ctrl+Alt) so OS WM_CHAR delivers special characters cleanly.
        let is_alt_gr = ks.modifiers.control && ks.modifiers.alt;
        let cmd = (ks.modifiers.control || ks.modifiers.platform) && !is_alt_gr;
        let word_mod = cmd || (ks.modifiers.alt && !ks.modifiers.control);
        let shift = ks.modifiers.shift;

        // Classic Windows clipboard shortcuts (Ctrl+Insert, Shift+Insert, Shift+Delete)
        match ks.key.as_str() {
            "insert" if cmd && !shift => {
                self.copy_selection(cx);
                cx.stop_propagation();
                return;
            }
            "insert" if shift && !cmd => {
                self.paste_clipboard(cx);
                cx.stop_propagation();
                return;
            }
            "delete" if shift && !cmd && !ks.modifiers.alt => {
                self.cut_selection(cx);
                cx.stop_propagation();
                return;
            }
            _ => {}
        }

        if cmd {
            match ks.key.as_str() {
                "a" | "A" => {
                    self.select_all(cx);
                    cx.stop_propagation();
                    return;
                }
                "c" | "C" => {
                    self.copy_selection(cx);
                    cx.stop_propagation();
                    return;
                }
                "x" | "X" => {
                    self.cut_selection(cx);
                    cx.stop_propagation();
                    return;
                }
                "v" | "V" => {
                    self.paste_clipboard(cx);
                    cx.stop_propagation();
                    return;
                }
                "z" | "Z" => {
                    if shift {
                        self.redo(cx);
                    } else {
                        self.undo(cx);
                    }
                    cx.stop_propagation();
                    return;
                }
                "y" | "Y" => {
                    self.redo(cx);
                    cx.stop_propagation();
                    return;
                }
                "u" | "U" => {
                    let line = line_bounds_for_offset(&self.value, self.multiline, self.cursor_offset());
                    let range = if !self.selected_range.is_empty() {
                        self.clamped_selection()
                    } else if self.multiline {
                        line.start..self.cursor_offset()
                    } else {
                        0..self.value.len()
                    };
                    self.apply_edit(range, "", LastEditKind::None, false, cx);
                    cx.stop_propagation();
                    return;
                }
                "backspace" => {
                    self.delete_backward(true, cx);
                    cx.stop_propagation();
                    return;
                }
                "delete" => {
                    self.delete_forward(true, cx);
                    cx.stop_propagation();
                    return;
                }
                "left" => {
                    let target = prev_word_boundary_in(&self.value, self.masked, self.cursor_offset());
                    if shift {
                        self.select_to(target, cx);
                    } else {
                        self.move_to(target, cx);
                    }
                    cx.stop_propagation();
                    return;
                }
                "right" => {
                    let target = next_word_boundary_in(&self.value, self.masked, self.cursor_offset());
                    if shift {
                        self.select_to(target, cx);
                    } else {
                        self.move_to(target, cx);
                    }
                    cx.stop_propagation();
                    return;
                }
                "home" => {
                    if shift {
                        self.select_to(0, cx);
                    } else {
                        self.move_to(0, cx);
                    }
                    cx.stop_propagation();
                    return;
                }
                "end" => {
                    let len = self.value.len();
                    if shift {
                        self.select_to(len, cx);
                    } else {
                        self.move_to(len, cx);
                    }
                    cx.stop_propagation();
                    return;
                }
                _ => {
                    // Consume unknown Ctrl+key combinations so they don't leak control chars.
                    cx.stop_propagation();
                    return;
                }
            }
        }

        match ks.key.as_str() {
            "backspace" => {
                self.delete_backward(word_mod, cx);
                cx.stop_propagation();
            }
            "delete" => {
                self.delete_forward(word_mod, cx);
                cx.stop_propagation();
            }
            "left" => {
                if shift {
                    let target = if word_mod {
                        prev_word_boundary_in(&self.value, self.masked, self.cursor_offset())
                    } else {
                        prev_char_boundary_in(&self.value, self.cursor_offset())
                    };
                    self.select_to(target, cx);
                } else if !self.selected_range.is_empty() && !word_mod {
                    self.move_to(self.clamped_selection().start, cx);
                } else {
                    let target = if word_mod {
                        prev_word_boundary_in(&self.value, self.masked, self.cursor_offset())
                    } else {
                        prev_char_boundary_in(&self.value, self.cursor_offset())
                    };
                    self.move_to(target, cx);
                }
                cx.stop_propagation();
            }
            "right" => {
                if shift {
                    let target = if word_mod {
                        next_word_boundary_in(&self.value, self.masked, self.cursor_offset())
                    } else {
                        next_char_boundary_in(&self.value, self.cursor_offset())
                    };
                    self.select_to(target, cx);
                } else if !self.selected_range.is_empty() && !word_mod {
                    self.move_to(self.clamped_selection().end, cx);
                } else {
                    let target = if word_mod {
                        next_word_boundary_in(&self.value, self.masked, self.cursor_offset())
                    } else {
                        next_char_boundary_in(&self.value, self.cursor_offset())
                    };
                    self.move_to(target, cx);
                }
                cx.stop_propagation();
            }
            "up" => {
                self.move_vertical(-1, shift, cx);
                cx.stop_propagation();
            }
            "down" => {
                self.move_vertical(1, shift, cx);
                cx.stop_propagation();
            }
            "pageup" => {
                let page = self
                    .last_bounds
                    .map(|b| {
                        (f32::from(b.size.height) / f32::from(self.last_line_height.max(px(16.0))))
                            .floor()
                            .max(1.0) as isize
                    })
                    .unwrap_or(8);
                self.move_vertical(-page, shift, cx);
                cx.stop_propagation();
            }
            "pagedown" => {
                let page = self
                    .last_bounds
                    .map(|b| {
                        (f32::from(b.size.height) / f32::from(self.last_line_height.max(px(16.0))))
                            .floor()
                            .max(1.0) as isize
                    })
                    .unwrap_or(8);
                self.move_vertical(page, shift, cx);
                cx.stop_propagation();
            }
            "home" => {
                let target = line_bounds_for_offset(&self.value, self.multiline, self.cursor_offset()).start;
                if shift {
                    self.select_to(target, cx);
                } else {
                    self.move_to(target, cx);
                }
                cx.stop_propagation();
            }
            "end" => {
                let target = line_bounds_for_offset(&self.value, self.multiline, self.cursor_offset()).end;
                if shift {
                    self.select_to(target, cx);
                } else {
                    self.move_to(target, cx);
                }
                cx.stop_propagation();
            }
            "enter" => {
                if self.multiline {
                    let sel = self.clamped_selection();
                    self.apply_edit(sel, "\n", LastEditKind::None, false, cx);
                } else {
                    cx.emit(TextFieldEvent::Submit(self.value.clone()));
                }
                cx.stop_propagation();
            }
            "escape" => {
                if !self.multiline {
                    cx.emit(TextFieldEvent::Cancel);
                    cx.stop_propagation();
                }
            }
            "tab"
                if self.multiline => {
                    let sel = self.clamped_selection();
                    self.apply_edit(sel, "    ", LastEditKind::None, false, cx);
                    cx.stop_propagation();
                }
                // In single-line inputs, let Tab propagate for standard focus navigation.
            _ => {
                // Printable characters, Space, AltGr, dead keys, and IME input are intentionally
                // NOT stopped here so GPUI's platform input pipeline routes them through
                // `EntityInputHandler::replace_text_in_range` / `replace_and_mark_text_in_range`.
            }
        }
    }
}

impl EntityInputHandler for TextField {
    fn text_for_range(
        &mut self,
        range_utf16: Range<usize>,
        actual_range: &mut Option<Range<usize>>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<String> {
        let start = offset_from_utf16_in(&self.value, range_utf16.start);
        let end = offset_from_utf16_in(&self.value, range_utf16.end).max(start);
        actual_range.replace(
            offset_to_utf16_in(&self.value, start)..offset_to_utf16_in(&self.value, end),
        );
        Some(self.value[start..end].to_string())
    }

    fn selected_text_range(
        &mut self,
        _ignore_disabled_input: bool,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<UTF16Selection> {
        let sel = self.clamped_selection();
        Some(UTF16Selection {
            range: offset_to_utf16_in(&self.value, sel.start)
                ..offset_to_utf16_in(&self.value, sel.end),
            reversed: self.selection_reversed,
        })
    }

    fn marked_text_range(
        &self,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Range<usize>> {
        self.marked_range.as_ref().map(|r| {
            let start = clamp_char_boundary(&self.value, r.start);
            let end = clamp_char_boundary(&self.value, r.end).max(start);
            offset_to_utf16_in(&self.value, start)..offset_to_utf16_in(&self.value, end)
        })
    }

    fn unmark_text(&mut self, _window: &mut Window, cx: &mut Context<Self>) {
        if self.marked_range.take().is_some() {
            cx.notify();
        }
    }

    fn replace_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range_utf16
            .as_ref()
            .map(|r| {
                let s = offset_from_utf16_in(&self.value, r.start);
                let e = offset_from_utf16_in(&self.value, r.end).max(s);
                s..e
            })
            .or_else(|| self.marked_range.clone())
            .unwrap_or_else(|| self.clamped_selection());

        let clean = self.sanitize_text(new_text);
        let is_single_non_ws = clean.chars().count() == 1
            && clean
                .chars()
                .next()
                .map(|c| !c.is_whitespace())
                .unwrap_or(false);
        let can_coalesce = range.is_empty() && is_single_non_ws;
        self.apply_edit(range, &clean, LastEditKind::Insert, can_coalesce, cx);
    }

    fn replace_and_mark_text_in_range(
        &mut self,
        range_utf16: Option<Range<usize>>,
        new_text: &str,
        new_selected_range_utf16: Option<Range<usize>>,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let range = range_utf16
            .as_ref()
            .map(|r| {
                let s = offset_from_utf16_in(&self.value, r.start);
                let e = offset_from_utf16_in(&self.value, r.end).max(s);
                s..e
            })
            .or_else(|| self.marked_range.clone())
            .unwrap_or_else(|| self.clamped_selection());

        let start = clamp_char_boundary(&self.value, range.start);
        let end = clamp_char_boundary(&self.value, range.end).max(start);
        let clean = self.sanitize_text(new_text);

        if self.marked_range.is_none() {
            self.push_undo_if_needed(LastEditKind::None, false);
        }

        self.value.replace_range(start..end, &clean);
        if !clean.is_empty() {
            self.marked_range = Some(start..start + clean.len());
        } else {
            self.marked_range = None;
        }

        self.selected_range = new_selected_range_utf16
            .as_ref()
            .map(|rel_u16| {
                let rel_start = offset_from_utf16_in(&clean, rel_u16.start);
                let rel_end = offset_from_utf16_in(&clean, rel_u16.end).max(rel_start);
                (start + rel_start)..(start + rel_end)
            })
            .unwrap_or_else(|| (start + clean.len())..(start + clean.len()));
        self.selection_reversed = false;
        self.ensure_cursor_visible = true;
        self.reset_blink(cx);
        cx.emit(TextFieldEvent::Changed(self.value.clone()));
        cx.notify();
    }

    fn bounds_for_range(
        &mut self,
        range_utf16: Range<usize>,
        bounds: Bounds<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<Bounds<Pixels>> {
        let start = offset_from_utf16_in(&self.value, range_utf16.start);
        let end = offset_from_utf16_in(&self.value, range_utf16.end).max(start);
        let line_idx = self.line_index_for_offset(start);
        let x0 = self.x_for_offset_on_line(line_idx, start);
        let x1 = self.x_for_offset_on_line(line_idx, end);
        let line_h = self.last_line_height.max(px(16.0));
        let y0 = bounds.top() + line_h * (line_idx as f32) - self.scroll_y;
        Some(Bounds::from_corners(
            point(bounds.left() + x0 - self.scroll_x, y0),
            point(bounds.left() + x1 - self.scroll_x, y0 + line_h),
        ))
    }

    fn character_index_for_point(
        &mut self,
        point: Point<Pixels>,
        _window: &mut Window,
        _cx: &mut Context<Self>,
    ) -> Option<usize> {
        let utf8_idx = self.index_for_mouse_position(point, false);
        Some(offset_to_utf16_in(&self.value, utf8_idx))
    }
}

struct TextFieldElement {
    input: Entity<TextField>,
    palette: ThemePalette,
}

struct PrepaintState {
    lines: Vec<ShapedLineEntry>,
    placeholder_line: Option<ShapedLine>,
    selection_quads: Vec<PaintQuad>,
    caret_quad: Option<PaintQuad>,
    line_height: Pixels,
    scroll_x: Pixels,
    scroll_y: Pixels,
}

impl IntoElement for TextFieldElement {
    type Element = Self;

    fn into_element(self) -> Self::Element {
        self
    }
}

impl Element for TextFieldElement {
    type RequestLayoutState = ();
    type PrepaintState = PrepaintState;

    fn id(&self) -> Option<ElementId> {
        None
    }

    fn source_location(&self) -> Option<&'static core::panic::Location<'static>> {
        None
    }

    fn request_layout(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        window: &mut Window,
        cx: &mut App,
    ) -> (LayoutId, Self::RequestLayoutState) {
        let multiline = self.input.read(cx).multiline;
        let mut style = Style::default();
        style.size.width = relative(1.0).into();
        if multiline {
            style.size.height = relative(1.0).into();
        } else {
            style.size.height = window.line_height().into();
        }
        (window.request_layout(style, [], cx), ())
    }

    fn prepaint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        window: &mut Window,
        cx: &mut App,
    ) -> Self::PrepaintState {
        let input = self.input.read(cx);
        let focused = input.focus_handle.is_focused(window);
        let style = window.text_style();
        let font_size = style.font_size.to_pixels(window.rem_size());
        let line_height = window.line_height().max(font_size * 1.35);
        let font = style.font();
        let text_color = self.palette.text_primary;
        let muted_color = self.palette.text_muted;
        let accent = self.palette.accent;

        let value = &input.value;
        let masked = input.masked;
        let multiline = input.multiline;
        let selected_range = input.clamped_selection();
        let cursor = input.cursor_offset();
        let marked_range = input.marked_range.clone();
        let caret_visible = input.caret_visible;

        let ranges = line_ranges(value, multiline);
        let mut shaped_lines = Vec::with_capacity(ranges.len());
        let mut max_line_width = px(0.0);

        for range in ranges {
            let line_text = &value[range.clone()];
            let display: SharedString = if masked {
                MASK_CHAR.to_string().repeat(line_text.chars().count()).into()
            } else {
                line_text.to_string().into()
            };

            let base_run = TextRun {
                len: display.len(),
                font: font.clone(),
                color: text_color,
                background_color: None,
                underline: None,
                strikethrough: None,
            };

            let runs: Vec<TextRun> = if display.is_empty() {
                Vec::new()
            } else if let Some(ref marked) = marked_range {
                let m_start = marked.start.max(range.start).min(range.end);
                let m_end = marked.end.max(range.start).min(range.end);
                if m_start < m_end {
                    let d_start = line_value_to_display(line_text, masked, m_start - range.start);
                    let d_end = line_value_to_display(line_text, masked, m_end - range.start);
                    vec![
                        TextRun {
                            len: d_start,
                            ..base_run.clone()
                        },
                        TextRun {
                            len: d_end.saturating_sub(d_start),
                            underline: Some(UnderlineStyle {
                                color: Some(text_color),
                                thickness: px(1.0),
                                wavy: false,
                            }),
                            ..base_run.clone()
                        },
                        TextRun {
                            len: display.len().saturating_sub(d_end),
                            ..base_run
                        },
                    ]
                    .into_iter()
                    .filter(|r| r.len > 0)
                    .collect()
                } else {
                    vec![base_run]
                }
            } else {
                vec![base_run]
            };

            let shaped = window
                .text_system()
                .shape_line(display, font_size, &runs, None);
            if shaped.width > max_line_width {
                max_line_width = shaped.width;
            }
            shaped_lines.push(ShapedLineEntry { range, shaped });
        }

        let placeholder_line = if value.is_empty() && !input.placeholder.is_empty() {
            let run = TextRun {
                len: input.placeholder.len(),
                font: font.clone(),
                color: muted_color,
                background_color: None,
                underline: None,
                strikethrough: None,
            };
            Some(window.text_system().shape_line(
                input.placeholder.clone(),
                font_size,
                &[run],
                None,
            ))
        } else {
            None
        };

        // Locate active cursor (line_idx, cursor_x, cursor_y) in content coordinates.
        let mut cursor_line_idx = shaped_lines.len().saturating_sub(1);
        for (i, entry) in shaped_lines.iter().enumerate() {
            if cursor >= entry.range.start && cursor <= entry.range.end {
                cursor_line_idx = i;
                break;
            }
        }
        let cursor_x = shaped_lines
            .get(cursor_line_idx)
            .map(|entry| {
                let line_text = &value[entry.range.clone()];
                let local = cursor
                    .saturating_sub(entry.range.start)
                    .min(line_text.len());
                let disp = line_value_to_display(line_text, masked, local);
                entry.shaped.x_for_index(disp)
            })
            .unwrap_or(px(0.0));
        let cursor_y = line_height * (cursor_line_idx as f32);

        // Compute updated scroll offsets so active cursor stays visible inside bounds.
        let mut scroll_x = input.scroll_x;
        let mut scroll_y = input.scroll_y;
        let vw = bounds.size.width.max(px(1.0));
        let vh = bounds.size.height.max(px(1.0));

        if input.ensure_cursor_visible {
            let caret_pad = px(3.0);
            if cursor_x < scroll_x {
                scroll_x = cursor_x;
            } else if cursor_x + caret_pad > scroll_x + vw {
                scroll_x = cursor_x + caret_pad - vw;
            }
            if multiline {
                if cursor_y < scroll_y {
                    scroll_y = cursor_y;
                } else if cursor_y + line_height > scroll_y + vh {
                    scroll_y = cursor_y + line_height - vh;
                }
            }
        }

        let max_scroll_x = (max_line_width + px(4.0) - vw).max(px(0.0));
        scroll_x = scroll_x.clamp(px(0.0), max_scroll_x);
        if multiline {
            let total_h = line_height * (shaped_lines.len().max(1) as f32);
            let max_scroll_y = (total_h - vh).max(px(0.0));
            scroll_y = scroll_y.clamp(px(0.0), max_scroll_y);
        } else {
            scroll_y = px(0.0);
        }

        // Build selection highlight quads.
        let mut selection_quads = Vec::new();
        if !selected_range.is_empty() {
            let sel_bg = if focused {
                accent.opacity(0.28)
            } else {
                muted_color.opacity(0.18)
            };
            for (i, entry) in shaped_lines.iter().enumerate() {
                if selected_range.end <= entry.range.start && i > 0 {
                    break;
                }
                let line_y = bounds.top() + line_height * (i as f32) - scroll_y;
                if line_y + line_height < bounds.top() || line_y > bounds.bottom() {
                    continue;
                }

                let overlaps = selected_range.start < entry.range.end
                    && selected_range.end > entry.range.start;
                let covers_empty_line = entry.range.is_empty()
                    && selected_range.start <= entry.range.start
                    && selected_range.end > entry.range.end;

                if !overlaps && !covers_empty_line {
                    continue;
                }

                let line_text = &value[entry.range.clone()];
                let s_local = selected_range
                    .start
                    .max(entry.range.start)
                    .saturating_sub(entry.range.start)
                    .min(line_text.len());
                let e_local = selected_range
                    .end
                    .min(entry.range.end)
                    .saturating_sub(entry.range.start)
                    .min(line_text.len());
                let x0 = entry
                    .shaped
                    .x_for_index(line_value_to_display(line_text, masked, s_local));
                let mut x1 = entry
                    .shaped
                    .x_for_index(line_value_to_display(line_text, masked, e_local));
                if multiline && selected_range.end > entry.range.end {
                    x1 += px(6.0);
                }

                if x1 > x0 {
                    let mut quad = fill(
                        Bounds::from_corners(
                            point(bounds.left() + x0 - scroll_x, line_y),
                            point(bounds.left() + x1 - scroll_x, line_y + line_height),
                        ),
                        sel_bg,
                    );
                    quad.corner_radii = Corners::all(px(2.5));
                    selection_quads.push(quad);
                }
            }
        }

        // Build crisp rounded caret bar when focused with collapsed selection.
        let caret_quad = if focused && selected_range.is_empty() && caret_visible {
            let caret_h = (line_height - px(2.0)).max(px(14.0));
            let caret_y = bounds.top() + cursor_y - scroll_y + (line_height - caret_h) * 0.5;
            let caret_x = (bounds.left() + cursor_x - scroll_x).max(bounds.left());
            let mut quad = fill(
                Bounds::new(point(caret_x, caret_y), size(px(2.0), caret_h)),
                accent,
            );
            quad.corner_radii = Corners::all(px(1.0));
            Some(quad)
        } else {
            None
        };

        PrepaintState {
            lines: shaped_lines,
            placeholder_line,
            selection_quads,
            caret_quad,
            line_height,
            scroll_x,
            scroll_y,
        }
    }

    fn paint(
        &mut self,
        _id: Option<&GlobalElementId>,
        _inspector_id: Option<&gpui::InspectorElementId>,
        bounds: Bounds<Pixels>,
        _request_layout: &mut Self::RequestLayoutState,
        prepaint: &mut Self::PrepaintState,
        window: &mut Window,
        cx: &mut App,
    ) {
        let (focus_handle, is_selecting) = {
            let input = self.input.read(cx);
            (input.focus_handle.clone(), input.is_selecting)
        };

        // Register OS IME / character input handler for this focused text field.
        window.handle_input(
            &focus_handle,
            ElementInputHandler::new(bounds, self.input.clone()),
            cx,
        );

        // Track window-wide drag & release while selecting so dragging outside input bounds
        // continues selecting and auto-scrolling smoothly, just like HTML5 <input>.
        if is_selecting {
            let input_move = self.input.clone();
            window.on_mouse_event(move |event: &MouseMoveEvent, phase, window, cx| {
                if phase == DispatchPhase::Bubble {
                    input_move.update(cx, |this, cx| {
                        this.handle_mouse_move(event, window, cx);
                    });
                }
            });

            let input_up = self.input.clone();
            window.on_mouse_event(move |event: &MouseUpEvent, phase, window, cx| {
                if phase == DispatchPhase::Bubble && event.button == MouseButton::Left {
                    input_up.update(cx, |this, cx| {
                        this.handle_mouse_up(event, window, cx);
                    });
                }
            });
        }

        let line_height = prepaint.line_height;
        let scroll_x = prepaint.scroll_x;
        let scroll_y = prepaint.scroll_y;

        // Clip all painted selection, text, and caret cleanly within the text viewport.
        window.with_content_mask(Some(ContentMask { bounds }), |window| {
            for quad in prepaint.selection_quads.drain(..) {
                window.paint_quad(quad);
            }

            if let Some(placeholder) = prepaint.placeholder_line.take() {
                let _ = placeholder.paint(bounds.origin, line_height, window, cx);
            } else {
                for (i, entry) in prepaint.lines.iter().enumerate() {
                    let y = bounds.top() + line_height * (i as f32) - scroll_y;
                    if y + line_height < bounds.top() || y > bounds.bottom() {
                        continue;
                    }
                    let origin = point(bounds.left() - scroll_x, y);
                    let _ = entry.shaped.paint(origin, line_height, window, cx);
                }
            }

            if let Some(caret) = prepaint.caret_quad.take() {
                window.paint_quad(caret);
            }
        });

        let lines = std::mem::take(&mut prepaint.lines);
        self.input.update(cx, |input, _cx| {
            input.last_lines = lines;
            input.last_bounds = Some(bounds);
            input.last_line_height = line_height;
            input.scroll_x = scroll_x;
            input.scroll_y = scroll_y;
            input.ensure_cursor_visible = false;
        });
    }
}

impl Render for TextField {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let t = ThemePalette::from_settings(&UiSettings {
            theme_mode: self.theme_mode,
            accent: self.accent,
            ..Default::default()
        });
        let focused = self.focus_handle.is_focused(window);

        if focused && !self.was_focused {
            self.focus_epoch = self.focus_epoch.wrapping_add(1);
            self.was_focused = true;
            self.start_blink_loop(cx);
        } else if !focused && self.was_focused {
            self.was_focused = false;
            self.is_selecting = false;
            self.marked_range = None;
            self.stop_blink_loop();
        }

        // Animated bottom focus accent bar (expands cleanly from 0% -> 100% on focus)
        let focus_bar = focused.then(|| {
            div()
                .absolute()
                .bottom_0()
                .left_0()
                .right_0()
                .h(px(2.0))
                .flex()
                .justify_center()
                .child(
                    div()
                        .h_full()
                        .bg(t.accent)
                        .with_animation(
                            ("tf-focus-bar", self.focus_epoch),
                            Animation::new(Duration::from_millis(200))
                                .with_easing(ease_out_quint()),
                            |el, delta| el.w(relative(delta)),
                        ),
                )
        });

        let text_el = TextFieldElement {
            input: cx.entity(),
            palette: t,
        };

        let mut base = div()
            .track_focus(&self.focus_handle)
            .relative()
            .w_full()
            .border_1()
            .bg(t.bg_card)
            .border_color(if focused { t.accent } else { t.border_strong })
            .when(focused, |el| el.shadow_sm())
            .text_color(t.text_primary)
            .cursor(CursorStyle::IBeam)
            .hover(|s| {
                if focused {
                    s
                } else {
                    s.border_color(t.accent.opacity(0.5))
                }
            })
            .on_mouse_down(MouseButton::Left, cx.listener(Self::handle_mouse_down))
            .on_mouse_down(MouseButton::Right, cx.listener(Self::handle_right_mouse_down))
            .on_mouse_move(cx.listener(Self::handle_mouse_move))
            .on_mouse_up(MouseButton::Left, cx.listener(Self::handle_mouse_up))
            .on_mouse_up_out(MouseButton::Left, cx.listener(Self::handle_mouse_up))
            .on_key_down(cx.listener(Self::handle_key_down));

        if self.multiline {
            base = base
                .px_2p5()
                .py_1p5()
                .rounded_lg()
                .text_xs()
                .h(px(220.0))
                .min_h(px(140.0))
                .max_h(px(280.0))
                .flex()
                .flex_col()
                .font_family("Consolas")
                .overflow_hidden()
                .on_scroll_wheel(cx.listener(Self::handle_scroll_wheel));
        } else if self.compact {
            base = base
                .px_2()
                .py_0p5()
                .rounded_md()
                .text_size(px(11.0))
                .h(px(26.0))
                .flex()
                .items_center()
                .overflow_hidden();
        } else {
            base = base
                .px_2p5()
                .py_1p5()
                .rounded_lg()
                .text_xs()
                .h(px(34.0))
                .flex()
                .items_center()
                .overflow_hidden();
        }

        if self.monospace && !self.multiline {
            base = base.font_family("Consolas");
        }

        base.child(text_el).children(focus_bar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_click_word_boundaries() {
        let s = "prod-api_01 10.0.4.12";
        assert_eq!(&s[word_range_at(s, false, 0)], "prod");
        assert_eq!(&s[word_range_at(s, false, 2)], "prod");
        assert_eq!(&s[word_range_at(s, false, 4)], "-");
        assert_eq!(&s[word_range_at(s, false, 6)], "api_01");
        assert_eq!(&s[word_range_at(s, false, 11)], " ");
        assert_eq!(&s[word_range_at(s, false, 12)], "10");
        assert_eq!(&s[word_range_at(s, false, s.len())], "12");
    }

    #[test]
    fn double_click_masked_selects_all() {
        let s = "my secret-password";
        assert_eq!(word_range_at(s, true, 3), 0..s.len());
        assert_eq!(word_range_at("", true, 0), 0..0);
    }

    #[test]
    fn word_navigation_boundaries() {
        let s = "hello   world-123";
        assert_eq!(next_word_boundary_in(s, false, 0), 5);
        assert_eq!(next_word_boundary_in(s, false, 5), 13);
        assert_eq!(next_word_boundary_in(s, false, 13), 14);
        assert_eq!(next_word_boundary_in(s, false, 14), 17);

        assert_eq!(prev_word_boundary_in(s, false, 17), 14);
        assert_eq!(prev_word_boundary_in(s, false, 14), 13);
        assert_eq!(prev_word_boundary_in(s, false, 13), 8);
        assert_eq!(prev_word_boundary_in(s, false, 8), 0);
    }

    #[test]
    fn masked_display_index_roundtrip_utf8() {
        let s = "päss🚀!";
        for (byte_idx, _) in s.char_indices() {
            let disp = line_value_to_display(s, true, byte_idx);
            assert_eq!(line_display_to_value(s, true, disp), byte_idx);
        }
        let end_disp = line_value_to_display(s, true, s.len());
        assert_eq!(end_disp, 6 * MASK_CHAR.len_utf8());
        assert_eq!(line_display_to_value(s, true, end_disp), s.len());
    }

    #[test]
    fn utf16_conversion_with_surrogate_pair() {
        let s = "a🚀b";
        // 'a' = 1 UTF-16, '🚀' = 2 UTF-16 (4 UTF-8), 'b' = 1 UTF-16
        assert_eq!(offset_to_utf16_in(s, 0), 0);
        assert_eq!(offset_to_utf16_in(s, 1), 1);
        assert_eq!(offset_to_utf16_in(s, 5), 3);
        assert_eq!(offset_to_utf16_in(s, 6), 4);

        assert_eq!(offset_from_utf16_in(s, 0), 0);
        assert_eq!(offset_from_utf16_in(s, 1), 1);
        assert_eq!(offset_from_utf16_in(s, 3), 5);
        assert_eq!(offset_from_utf16_in(s, 4), 6);
    }

    #[test]
    fn multiline_line_ranges_and_bounds() {
        let s = "first\nsecond\n";
        assert_eq!(line_ranges(s, true), vec![0..5, 6..12, 13..13]);
        assert_eq!(line_bounds_for_offset(s, true, 2), 0..5);
        assert_eq!(line_bounds_for_offset(s, true, 6), 6..12);
        assert_eq!(line_bounds_for_offset(s, true, 13), 13..13);
        assert_eq!(line_bounds_for_offset(s, false, 7), 0..13);
    }
}
