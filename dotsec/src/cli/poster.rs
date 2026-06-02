//! `dotsec` with no subcommand renders this brand poster: a dark panel
//! with the `.sec` wordmark drawn from authentic Commodore 64 character
//! ROM bitmaps (sourced from cbmeeks/VgaPico's petscii/chargen, screen
//! codes period / s=19 / e=5 / c=3). Half-block characters collapse 2
//! source pixels into one terminal cell. The wordmark boots in as
//! scrambled cipher glyphs and resolves to the clean form; the MIT
//! license types in beneath; a one-line getting-started hint follows.

use chromakopia::animate::framebuffer::{secs_to_frames, Cell, FrameBuffer};
use chromakopia::animate::{Easing, Effect, Plasma, Scene};
use chromakopia::{gradient, Color};

// ── C64 character ROM glyphs. 8×8, MSB = leftmost pixel. ──

const CHAR_PERIOD: [&str; 8] = [
    "........", "........", "........", "........", "........", "...##...", "...##...", "........",
];

const CHAR_S: [&str; 8] = [
    "..####..", ".##..##.", ".##.....", "..####..", ".....##.", ".##..##.", "..####..", "........",
];

const CHAR_E: [&str; 8] = [
    ".######.", ".##.....", ".##.....", ".####...", ".##.....", ".##.....", ".######.", "........",
];

const CHAR_C: [&str; 8] = [
    "..####..", ".##..##.", ".##.....", ".##.....", ".##.....", ".##..##.", "..####..", "........",
];

/// Char glyphs in render order. Each is 8 cols wide × 8 rows tall.
const GLYPHS: &[&[&str; 8]] = &[&CHAR_PERIOD, &CHAR_S, &CHAR_E, &CHAR_C];
/// Real visible gap (in source pixels) between glyphs after the C64's
/// built-in side padding is trimmed off.
const KERN: usize = 1;
/// Each source pixel renders as SCALE×SCALE cells before the half-block
/// vertical collapse. 1 = tiny, 2 = chunky retro.
const SCALE: usize = 2;

const PANEL_BG: Color = Color {
    r: 200,
    g: 154,
    b: 50,
};
/// Quick-start commands shown above the MIT license block. Two flavours:
/// the local provider (zero config) and AWS KMS (for teams already on AWS).
/// Empty strings render as blank rows for vertical breathing room.
const QUICK_START_LINES: &[&str] = &[
    "Quick start with age (X25519 + ChaCha20-Poly1305, key file on disk):",
    "  dotsec set <KEY> <VALUE>",
    "  dotsec run -- node server.js",
    "",
    "Quick start with AWS KMS (IAM-controlled, CloudTrail-audited):",
    "  dotsec init                # one-time: pick a KMS key + region",
    "  dotsec set <KEY> <VALUE>",
    "  dotsec run -- node server.js",
];
const QUICK_START_FG: Color = Color { r: 40, g: 30, b: 8 };
const LICENSE_FG: Color = Color { r: 40, g: 30, b: 8 };
/// One-liner under the wordmark. The whole pitch in seven characters.
const TAGLINE: &str = ".env without the .env";
const TAGLINE_FG: Color = Color { r: 40, g: 30, b: 8 };
const PAD_X: usize = 4;
const PAD_TOP: usize = 2;
const PAD_BOTTOM: usize = 2;
/// Blank rows between logo and tagline.
const GAP_LOGO_TAGLINE: usize = 1;
/// Blank rows between tagline and quick-start.
const GAP_TAGLINE_QUICK_START: usize = 1;
/// Blank rows between quick-start and license.
const GAP_QUICK_START_LICENSE: usize = 2;

/// Leftmost and rightmost lit columns of a glyph (inclusive). Lets us
/// strip the C64's built-in left/right padding so KERN controls the real
/// visible gap.
fn glyph_bounds(glyph: &[&str; 8]) -> (usize, usize) {
    let mut left = 8;
    let mut right = 0;
    for row in glyph.iter() {
        for (x, ch) in row.chars().enumerate() {
            if ch == '#' {
                if x < left {
                    left = x;
                }
                if x > right {
                    right = x;
                }
            }
        }
    }
    (left, right)
}

/// Build the full wordmark pixel grid by placing each glyph at its actual
/// visible bounds with KERN pixels of gap between.
fn build_pixels() -> Vec<Vec<bool>> {
    let glyph_h = 8;
    let bounds: Vec<(usize, usize)> = GLYPHS.iter().map(|g| glyph_bounds(g)).collect();
    let trimmed_widths: Vec<usize> = bounds.iter().map(|(l, r)| r - l + 1).collect();
    let total_w = (trimmed_widths.iter().sum::<usize>() + KERN * (GLYPHS.len() - 1)) * SCALE;
    let total_h = glyph_h * SCALE;
    let mut grid = vec![vec![false; total_w]; total_h];

    let mut x_cursor = 0usize;
    for (i, glyph) in GLYPHS.iter().enumerate() {
        let (gleft, _) = bounds[i];
        for (gy, row) in glyph.iter().enumerate() {
            for (gx, ch) in row.chars().enumerate() {
                if ch != '#' {
                    continue;
                }
                let trimmed_x = gx - gleft;
                for sy in 0..SCALE {
                    for sx in 0..SCALE {
                        let px = (x_cursor + trimmed_x) * SCALE + sx;
                        let py = gy * SCALE + sy;
                        if py < total_h && px < total_w {
                            grid[py][px] = true;
                        }
                    }
                }
            }
        }
        x_cursor += trimmed_widths[i] + KERN;
    }
    grid
}

/// Pixel grid → terminal-cell char grid using half-block characters. Two
/// vertical pixels collapse into one cell (top/bottom = '▀'/'▄'/'█'/' ').
#[allow(clippy::needless_range_loop)] // indexed iteration is clearer here
fn pixels_to_halfblocks(pixels: &[Vec<bool>]) -> Vec<Vec<char>> {
    let h_px = pixels.len();
    let w_px = pixels.first().map(|r| r.len()).unwrap_or(0);
    let h_cells = h_px.div_ceil(2);

    let mut out = vec![vec![' '; w_px]; h_cells];
    for cy in 0..h_cells {
        for cx in 0..w_px {
            let top = pixels
                .get(cy * 2)
                .and_then(|r| r.get(cx))
                .copied()
                .unwrap_or(false);
            let bot = pixels
                .get(cy * 2 + 1)
                .and_then(|r| r.get(cx))
                .copied()
                .unwrap_or(false);
            out[cy][cx] = match (top, bot) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                _ => ' ',
            };
        }
    }
    out
}

const LICENSE_TEXT: &str = r#"MIT License

Copyright (c) 2026 JP Wesselink

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE."#;

/// Everything in one rectangle, stacked top-down: .sec logo, credit line,
/// MIT license. Sized up-front so the rectangle never resizes.
struct DotsecPoster {
    logo_art: Vec<Vec<char>>,
    logo_w: usize,
    logo_h: usize,
    tagline_chars: Vec<char>,
    license_lines: Vec<Vec<char>>,
    panel_w: usize,
    panel_h: usize,
    logo_x: usize,
    logo_y: usize,
    tagline_x: usize,
    tagline_y: usize,
    quick_start_x: usize,
    quick_start_y: usize,
    license_x: usize,
    license_y: usize,
    entrance_frames: usize,
    resolve_frames: usize,
    type_start: usize,
    type_chars_per_sec: f64,
    scramble_frames: usize,
    plasma: Plasma,
}

impl DotsecPoster {
    fn new(
        entrance_secs: f64,
        resolve_secs: f64,
        type_delay_secs: f64,
        type_chars_per_sec: f64,
    ) -> Self {
        let pixels = build_pixels();
        let logo_art = pixels_to_halfblocks(&pixels);
        let logo_w = logo_art.first().map(|r| r.len()).unwrap_or(0);
        let logo_h = logo_art.len();

        let license_lines: Vec<Vec<char>> =
            LICENSE_TEXT.lines().map(|l| l.chars().collect()).collect();
        let license_w = license_lines.iter().map(|l| l.len()).max().unwrap_or(0);
        let license_h = license_lines.len();
        let tagline_chars: Vec<char> = TAGLINE.chars().collect();
        let tagline_w = tagline_chars.len();
        let quick_start_w = QUICK_START_LINES
            .iter()
            .map(|l| l.chars().count())
            .max()
            .unwrap_or(0);
        let quick_start_h = QUICK_START_LINES.len();

        let content_w = logo_w.max(tagline_w).max(quick_start_w).max(license_w);
        let panel_w = content_w + 2 * PAD_X;
        let panel_h = PAD_TOP
            + logo_h
            + GAP_LOGO_TAGLINE
            + 1 // tagline is one line
            + GAP_TAGLINE_QUICK_START
            + quick_start_h
            + GAP_QUICK_START_LICENSE
            + license_h
            + PAD_BOTTOM;

        // Center the logo + tagline within the content width. The
        // quick-start and license blocks stay left-aligned (they read better
        // that way).
        let logo_x = PAD_X + content_w.saturating_sub(logo_w) / 2;
        let logo_y = PAD_TOP;
        let tagline_y = logo_y + logo_h + GAP_LOGO_TAGLINE;
        let tagline_x = PAD_X + content_w.saturating_sub(tagline_w) / 2;
        let quick_start_x = PAD_X;
        let quick_start_y = tagline_y + 1 + GAP_TAGLINE_QUICK_START;
        let license_x = PAD_X;
        let license_y = quick_start_y + quick_start_h + GAP_QUICK_START_LICENSE;

        let palette =
            gradient(&["#000000", "#000000", "#806014", "#000000", "#000000"]).palette(128);
        let plasma = Plasma::new().palette(palette);

        Self {
            logo_art,
            logo_w,
            logo_h,
            tagline_chars,
            license_lines,
            panel_w,
            panel_h,
            logo_x,
            logo_y,
            tagline_x,
            tagline_y,
            quick_start_x,
            quick_start_y,
            license_x,
            license_y,
            entrance_frames: secs_to_frames(entrance_secs),
            resolve_frames: secs_to_frames(resolve_secs),
            // License starts as soon as the entrance settles (in parallel
            // with the .sec scramble). `type_delay_secs` adjusts from there.
            type_start: secs_to_frames(entrance_secs + type_delay_secs),
            type_chars_per_sec,
            scramble_frames: 6,
            plasma,
        }
    }
}

impl Effect for DotsecPoster {
    fn render(&self, buf: &mut FrameBuffer, frame: usize) {
        use rand::Rng;
        let mut rng = rand::rng();
        let glitch: Vec<char> = "!@#$%^&*<>[]{}|/\\~`+=?".chars().collect();

        let buf_w = buf.width;
        let buf_h = buf.height;

        // Entrance: slide up from below with an elastic overshoot.
        let base_y0 = buf_h.saturating_sub(self.panel_h) / 2;
        let entrance_t = if self.entrance_frames == 0 {
            1.0
        } else {
            (frame as f64 / self.entrance_frames as f64).clamp(0.0, 1.0)
        };
        let eased = Easing::Elastic(0.35).apply(entrance_t);
        let y0_f = buf_h as f64 + eased * (base_y0 as f64 - buf_h as f64);
        let y0 = y0_f.round() as i32;

        // Scramble timing starts AFTER the entrance settles.
        let resolve_local = frame.saturating_sub(self.entrance_frames);
        let scramble = if resolve_local >= self.resolve_frames {
            0.0
        } else {
            let t = resolve_local as f64 / self.resolve_frames.max(1) as f64;
            (1.0 - t).powf(1.5)
        };

        // Plasma colour field (sized to panel).
        let mut plasma_buf = FrameBuffer::new(self.panel_w, self.panel_h);
        for py in 0..self.panel_h {
            for px in 0..self.panel_w {
                plasma_buf.set(px, py, Cell::new('█', Color::new(0, 0, 0)));
            }
        }
        self.plasma.render(&mut plasma_buf, frame);

        let x0 = buf_w.saturating_sub(self.panel_w) / 2;

        // Translate a panel-local (px, py) into buffer coords with the
        // entrance offset applied. Returns None if clipped.
        let to_buf = |px: usize, py: usize| -> Option<(usize, usize)> {
            let bx = x0 + px;
            let by = y0 + py as i32;
            if bx >= buf_w || by < 0 || by >= buf_h as i32 {
                return None;
            }
            Some((bx, by as usize))
        };

        // Panel background: solid gold.
        for py in 0..self.panel_h {
            for px in 0..self.panel_w {
                if let Some((bx, by)) = to_buf(px, py) {
                    buf.set(bx, by, Cell::with_bg(' ', PANEL_BG, PANEL_BG));
                }
            }
        }

        // Logo — half-blocks coloured by plasma, with cipher scramble
        // during the resolve phase (after entrance).
        for ry in 0..self.logo_h {
            for cx in 0..self.logo_w {
                let original = self.logo_art[ry][cx];
                if original == ' ' {
                    continue;
                }
                let Some((bx, by)) = to_buf(self.logo_x + cx, self.logo_y + ry) else {
                    continue;
                };
                let ch = if rng.random::<f64>() < scramble {
                    glitch[rng.random_range(0..glitch.len())]
                } else {
                    original
                };
                let fg = plasma_buf.get(self.logo_x + cx, self.logo_y + ry).color;
                buf.set(bx, by, Cell::with_bg(ch, fg, PANEL_BG));
            }
        }

        // Tagline + Quick-start block — fade in as the logo scramble settles.
        let qs_alpha = (1.0 - scramble).clamp(0.0, 1.0);
        let qs_color = Color::lerp_rgb(PANEL_BG, QUICK_START_FG, qs_alpha);
        let tagline_color = Color::lerp_rgb(PANEL_BG, TAGLINE_FG, qs_alpha);

        // Tagline — single line, centered under the wordmark.
        for (i, &ch) in self.tagline_chars.iter().enumerate() {
            let Some((bx, by)) = to_buf(self.tagline_x + i, self.tagline_y) else {
                continue;
            };
            buf.set(bx, by, Cell::with_bg(ch, tagline_color, PANEL_BG));
        }

        for (row, line) in QUICK_START_LINES.iter().enumerate() {
            for (i, ch) in line.chars().enumerate() {
                let Some((bx, by)) = to_buf(self.quick_start_x + i, self.quick_start_y + row)
                else {
                    continue;
                };
                buf.set(bx, by, Cell::with_bg(ch, qs_color, PANEL_BG));
            }
        }

        // License typewriter — starts after type_start.
        if frame >= self.type_start {
            const FPS: f64 = 30.0;
            let type_frame = frame - self.type_start;
            let frames_per_char = (FPS / self.type_chars_per_sec).max(0.001);
            let mut nonspace_idx = 0usize;
            for (ly, line) in self.license_lines.iter().enumerate() {
                for (lx, &ch) in line.iter().enumerate() {
                    if ch == ' ' {
                        continue;
                    }
                    let idx = nonspace_idx;
                    nonspace_idx += 1;
                    let Some((bx, by)) = to_buf(self.license_x + lx, self.license_y + ly) else {
                        continue;
                    };
                    let reveal = (idx as f64 * frames_per_char) as usize;
                    if type_frame < reveal {
                        continue;
                    }
                    let out = if type_frame - reveal < self.scramble_frames {
                        glitch[rng.random_range(0..glitch.len())]
                    } else {
                        ch
                    };
                    buf.set(bx, by, Cell::with_bg(out, LICENSE_FG, PANEL_BG));
                }
            }
        }
    }

    fn size(&self) -> (usize, usize) {
        (self.panel_w + 2, self.panel_h + 1)
    }
}

/// Render the brand poster. Called from `cli::parse_args` when `dotsec` is
/// invoked with no subcommand.
pub async fn show() {
    // entrance_secs (panel slide-in), resolve_secs (logo scramble),
    // type_delay_secs (beat after logo), type_chars_per_sec.
    let poster = DotsecPoster::new(2.0, 1.5, 0.0, 100.0);
    let total_secs = 22.0;

    // NO_COLOR / non-TTY: render the final settled frame as plain text.
    if !chromakopia::color_enabled() {
        let (w, h) = poster.size();
        let mut buf = FrameBuffer::new(w, h);
        poster.render(&mut buf, secs_to_frames(total_secs));
        println!("{}", buf.to_plain_string());
        return;
    }

    Scene::new().add(poster).run(total_secs).await;
}
