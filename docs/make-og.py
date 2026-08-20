#!/usr/bin/env python3
# Regenerates docs/og.svg (then: rsvg-convert -w 1200 -h 630 og.svg -o og.png).
# Palette is copied from index.html's :root — keep them in sync.
# Deliberately carries NO URL, so it survives a domain change.
# Source of og.png for knock-daemon: three interleaved knock sequences, each opening independently.
G, G2, PANEL, LINE, LSOFT = "#0E1421", "#0B111C", "#16202F", "#24334A", "#1B2740"
TEXT, MUTED, FAINT, AMBER = "#E7ECF4", "#94A2B8", "#5E6E86", "#F0A83A"
C1, C2, C3, OK = "#4FD6C1", "#8CA0FF", "#F0879B", "#5FD08A"
MONO = "Menlo, DejaVu Sans Mono, monospace"
SANS = "Helvetica Neue, Helvetica, DejaVu Sans, sans-serif"

W, H = 1200, 630
p = []
a = p.append
a(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">')
a('<defs>')
a(f'<linearGradient id="bg" x1="0" y1="0" x2="0.4" y2="1"><stop offset="0" stop-color="{G}"/><stop offset="1" stop-color="{G2}"/></linearGradient>')
# faint scanlines -> packet-capture console texture
a('<pattern id="scan" width="4" height="4" patternUnits="userSpaceOnUse">'
  f'<rect width="4" height="1" fill="{LSOFT}" opacity="0.30"/></pattern>')
a('</defs>')
a(f'<rect width="{W}" height="{H}" fill="url(#bg)"/>')
a(f'<rect width="{W}" height="{H}" fill="url(#scan)" opacity="0.5"/>')
# amber top rule = the brand's one accent
a(f'<rect x="0" y="0" width="{W}" height="5" fill="{AMBER}"/>')

PAD = 76
# --- eyebrow ---
a(f'<text x="{PAD}" y="118" font-family="{MONO}" font-size="19" letter-spacing="4.4" '
  f'fill="{AMBER}" font-weight="600">CONCURRENT PORT KNOCKING &#183; LINUX</text>')
# --- title ---
a(f'<text x="{PAD}" y="212" font-family="{MONO}" font-size="80" font-weight="700" '
  f'fill="{TEXT}" letter-spacing="-1">knock-daemon</text>')
# --- claim ---
a(f'<text x="{PAD}" y="266" font-family="{SANS}" font-size="30" fill="{MUTED}">'
  f'A <tspan fill="{TEXT}">knockd</tspan> replacement that doesn’t drop simultaneous knocks.</text>')

# --- the diagram: one shared timeline, three sources strictly interleaved ---
X0, X1 = 322, 936          # timeline span
SLOTS = 9
step = (X1 - X0) / (SLOTS - 1)
lanes = [
    ("10.0.0.4",   C1, 372, [0, 3, 6]),
    ("10.0.0.9",   C2, 444, [1, 4, 7]),
    ("10.0.0.21",  C3, 516, [2, 5, 8]),
]
# panel behind the diagram
a(f'<rect x="{PAD-20}" y="326" width="{W-2*(PAD-20)}" height="242" rx="14" fill="{PANEL}" '
  f'opacity="0.55" stroke="{LINE}" stroke-width="1"/>')
# time axis ticks
for i in range(SLOTS):
    x = X0 + step * i
    a(f'<rect x="{x-0.5:.1f}" y="344" width="1" height="200" fill="{LSOFT}"/>')

for label, col, y, slots in lanes:
    a(f'<text x="{X0-26}" y="{y+6}" font-family="{MONO}" font-size="18" fill="{col}" '
      f'text-anchor="end">{label}</text>')
    a(f'<rect x="{X0-8}" y="{y-0.5}" width="{X1-X0+16}" height="1" fill="{LINE}"/>')
    for s in slots:
        x = X0 + step * s
        a(f'<rect x="{x-11}" y="{y-11}" width="22" height="22" rx="4" fill="{col}"/>')
    # independent OPEN verdict
    bx = X1 + 34
    a(f'<rect x="{bx}" y="{y-17}" width="106" height="34" rx="17" fill="{OK}" opacity="0.14"/>')
    a(f'<circle cx="{bx+21}" cy="{y}" r="5" fill="{OK}"/>')
    a(f'<text x="{bx+36}" y="{y+6}" font-family="{MONO}" font-size="17" font-weight="700" '
      f'fill="{OK}">OPEN</text>')

# --- footer strip ---
a(f'<text x="{PAD}" y="600" font-family="{MONO}" font-size="18" fill="{FAINT}" letter-spacing="1.6">'
  f'Rust &#183; per-source-IP matching &#183; nftables &#183; AF_PACKET</text>')
a(f'<text x="{W-PAD}" y="600" font-family="{MONO}" font-size="18" fill="{FAINT}" '
  f'text-anchor="end" letter-spacing="1.6">MIT OR Apache-2.0</text>')
a('</svg>')

import pathlib
out = pathlib.Path(__file__).resolve().parent / "og.svg"
out.write_text("\n".join(p) + "\n")
print(f"wrote {out}")
