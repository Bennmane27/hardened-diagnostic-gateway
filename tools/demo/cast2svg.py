#!/usr/bin/env python3
"""
cast2svg.py

Convertit un enregistrement asciinema (.cast v2) en SVG anime autonome.

Pourquoi pas un GIF : un GIF de terminal pese plusieurs megaoctets, floute
le texte et n'est pas selectionnable. Un SVG anime tient dans quelques
dizaines de kilooctets, reste net a toute taille, et GitHub l'affiche
directement dans un README via une balise <img>.

Aucune dependance : uniquement la bibliotheque standard.

Usage :
    tools/demo/cast2svg.py docs/media/demo.cast docs/media/demo.svg
    tools/demo/cast2svg.py in.cast out.svg --rows 28 --fps 1.2
"""

import argparse
import json
import re
import sys

# Sequences ANSI. La demonstration n'en emet pas, mais un enregistrement
# futur pourrait en contenir : on les retire plutot que de les afficher.
ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[()][A-Z0-9]")

THEME = {
    "bg":      "#11151c",
    "fg":      "#c9d1d9",
    "dim":     "#6e7681",
    "accent":  "#58a6ff",
    "ok":      "#3fb950",
    "warn":    "#d29922",
    "bad":     "#f85149",
    "chrome":  "#1c2128",
}


class Screen:
    """Terminal minimal : ecriture, retour chariot, saut de ligne."""

    def __init__(self, cols):
        self.cols = cols
        self.lines = [""]
        self.col = 0

    def write(self, text):
        for ch in text:
            if ch == "\n":
                self.lines.append("")
                self.col = 0
            elif ch == "\r":
                self.col = 0
            elif ch == "\b":
                self.col = max(0, self.col - 1)
            elif ch == "\t":
                self.col = (self.col // 8 + 1) * 8
            elif ch >= " ":
                line = self.lines[-1]
                if len(line) < self.col:
                    line = line + " " * (self.col - len(line))
                self.lines[-1] = line[:self.col] + ch + line[self.col + 1:]
                self.col += 1
                if self.col >= self.cols:
                    self.lines.append("")
                    self.col = 0

    def tail(self, rows):
        out = self.lines[-rows:]
        return out + [""] * (rows - len(out))


def classify(line):
    """Couleur d'une ligne, d'apres son contenu."""
    if "ANOMALIES" in line or "REFUS" in line or "ECHEC" in line:
        return "bad" if ("ECHEC" in line) else "warn"
    if line.strip().startswith("OK") or " OK " in line or "OK  " in line:
        return "ok"
    if "═" in line or line.strip().startswith("["):
        return "accent"
    if "TX " in line or "RX " in line:
        return "dim"
    return "fg"


def escape(text):
    return (text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;"))


def build_frames(events, cols, rows, fps):
    """Echantillonne l'ecran a intervalle regulier."""
    screen = Screen(cols)
    frames = []
    step = 1.0 / fps
    next_at = 0.0

    for when, kind, data in events:
        if kind != "o":
            continue
        while when >= next_at:
            frames.append((next_at, screen.tail(rows)))
            next_at += step
        screen.write(ANSI.sub("", data))

    frames.append((next_at, screen.tail(rows)))
    return frames


def dedupe(frames):
    """Supprime les images identiques a la precedente."""
    out = []
    for when, lines in frames:
        if out and out[-1][1] == lines:
            continue
        out.append((when, lines))
    return out


def render(frames, total, cols, rows, char_w, line_h, font_size, hold):
    pad_x, pad_y, chrome_h = 18, 14, 30
    width = int(cols * char_w + 2 * pad_x)
    height = int(rows * line_h + 2 * pad_y + chrome_h)
    duration = total + hold

    css = [
        f".t{{font-family:'SFMono-Regular',Consolas,'DejaVu Sans Mono',"
        f"monospace;font-size:{font_size}px;white-space:pre}}",
        ".f{visibility:hidden}",
    ]
    for name, colour in THEME.items():
        css.append(f".{name}{{fill:{colour}}}")

    body = []
    for index, (when, lines) in enumerate(frames):
        end = frames[index + 1][0] if index + 1 < len(frames) else duration
        start_pct = 100.0 * when / duration
        end_pct = 100.0 * end / duration

        css.append(
            f"#f{index}{{animation:a{index} {duration:.2f}s infinite}}"
        )
        css.append(
            f"@keyframes a{index}{{"
            f"0%,{start_pct:.4f}%{{visibility:hidden}}"
            f"{start_pct:.4f}%,{end_pct:.4f}%{{visibility:visible}}"
            f"{end_pct:.4f}%,100%{{visibility:hidden}}}}"
        )

        parts = [f'<g class="f" id="f{index}">']
        for row, line in enumerate(lines):
            if not line.strip():
                continue
            y = pad_y + chrome_h + (row + 1) * line_h - 4
            parts.append(
                f'<text class="t {classify(line)}" x="{pad_x}" '
                f'y="{y:.0f}">{escape(line)}</text>'
            )
        parts.append("</g>")
        body.append("".join(parts))

    dots = "".join(
        f'<circle cx="{18 + i * 18}" cy="16" r="5.5" fill="{c}"/>'
        for i, c in enumerate(("#f85149", "#d29922", "#3fb950"))
    )

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
        f'height="{height}" viewBox="0 0 {width} {height}">'
        f"<style>{''.join(css)}</style>"
        f'<rect width="{width}" height="{height}" rx="8" fill="{THEME["bg"]}"/>'
        f'<rect width="{width}" height="{chrome_h}" rx="8" '
        f'fill="{THEME["chrome"]}"/>'
        f'<rect y="{chrome_h - 8}" width="{width}" height="8" '
        f'fill="{THEME["chrome"]}"/>'
        f"{dots}"
        f'<text x="{width / 2:.0f}" y="21" text-anchor="middle" '
        f'class="t dim" font-size="12">hardened-diagnostic-gateway</text>'
        f"{''.join(body)}"
        "</svg>"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cast")
    ap.add_argument("svg")
    ap.add_argument("--rows", type=int, default=30)
    ap.add_argument("--fps", type=float, default=1.4,
                    help="images par seconde echantillonnees")
    ap.add_argument("--font-size", type=float, default=13.0)
    ap.add_argument("--hold", type=float, default=3.0,
                    help="secondes d'arret sur la derniere image")
    args = ap.parse_args()

    with open(args.cast, encoding="utf-8") as handle:
        raw = handle.read().splitlines()

    header = json.loads(raw[0])
    events = [json.loads(line) for line in raw[1:] if line.strip()]
    cols = header.get("width", 100)

    frames = dedupe(build_frames(events, cols, args.rows, args.fps))
    total = events[-1][0] if events else 1.0

    char_w = args.font_size * 0.602      # avance d'une police monospace
    line_h = args.font_size * 1.38

    svg = render(frames, total, cols, args.rows,
                 char_w, line_h, args.font_size, args.hold)

    with open(args.svg, "w", encoding="utf-8") as handle:
        handle.write(svg)

    print(f"{args.svg} : {len(frames)} images, "
          f"{total + args.hold:.1f} s, {len(svg) / 1024:.0f} Ko")
    return 0


if __name__ == "__main__":
    sys.exit(main())
