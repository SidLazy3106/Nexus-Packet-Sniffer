# NEXUS design system - master

> Source of truth for the app UI (and the future website). Page overrides live in `pages/<name>.md`.
> Generated with the ui-ux-pro-max `--design-system` tool (Variance 3 · Motion 2 · Density 8), then
> **corrected by hand**: the tool proposed a landing-page pattern and a lavender light palette
> (wellness category), which do not fit a packet analyzer or the wabi-sabi direction chosen by the owner.

## Direction: wabi-sabi

Quiet, worn, natural. Beauty from restraint and imperfection: generous negative space, muted earthy colour,
asymmetry, visible craft (the paper grain, the unclosed ensō, a single gold "kintsugi" seam to mark the active place).
No neon, no glossy gradients, no decorative charts. Data legibility and accessibility always win.

## Tokens (defined once in `src/index.css`; code reads them as `var(--c-*)` via `src/lib/palette.ts`)

Layer 1 - primitives (traditional pigments)

| Token | Value | Use |
|---|---|---|
| `--sumi-950/900/850/800/700/600` | `#110f0d` `#171512` `#1d1a16` `#25211c` `#36312a` `#4b453b` | ink-black backgrounds, lines |
| `--kinari-100/300/500` | `#ece5d6` `#c4bba8` `#9a9280` | unbleached-silk text: primary / secondary / tertiary |
| `--aizome-400/600/700` | `#8aa3bd` `#4c6480` `#3a4f68` | indigo: links, selection, primary button |
| `--seiji-400` | `#9cc0b0` | celadon: UDP, low severity |
| `--koke-400` | `#a3b27b` | moss: healthy / confirmed |
| `--kincha-400` | `#cfaa5e` | aged gold: warning, active-place seam |
| `--kaki-400` | `#d48e66` | persimmon: high severity |
| `--akane-400` | `#d26f5e` | madder red: critical / errors |
| `--fuji-400`, `--sunairo-400` | `#ae9fc2` `#a79d84` | wisteria (DNS), sand (DHCP) |

Layer 2 - semantic: `--c-bg --c-surface --c-raised --c-inset --c-line --c-line-soft --c-ink --c-dim --c-faint --c-accent --c-celadon --c-ok --c-warn --c-orange --c-crit --c-wisteria --c-sand`.
Layer 3 - component: `--card-*`, `--btn-*`, `--radius` (6px), `--radius-lg` (9px), `--ease-quiet`, `--dur` (220ms).

Contrast (measured against `--c-bg` / `--c-surface`): ink ≈ 14:1, dim ≈ 9:1, faint ≥ 5:1. Severity is never colour-only: every badge carries its text label.

## Type

- Headings and large figures: **Lora Variable** (OFL, bundled locally - NEXUS never fetches web fonts), weight 500.
- Interface and data: Segoe UI Variable. Packet data: Cascadia Mono / Consolas, tabular numerals.
- Base 13px (dense dashboard); body line-height 1.5; no text below 11px.

## Shape, texture, motion

- Hairline borders, flat surfaces, 6-9px radii, no drop shadows except toasts. Paper-grain overlay at 4.5% opacity.
- Motion (GSAP, `power1.out`, 300-400ms): pages settle in 8px; the ensō draws once. Colour/border transitions 220ms.
  Everything honours `prefers-reduced-motion` (GSAP `matchMedia` and CSS). Never animate width/height; never `transition: all`.

## Checklist (from ui-ux-pro-max / hallmark floor, applied)

- [x] Every colour is a token; no literal colour in components
- [x] Visible `:focus-visible` ring on every interactive element
- [x] `cursor: pointer` on clickable elements; hover states 150-300ms
- [x] Reduced-motion fallback for every animation
- [x] SVG icons only (Lucide), no emoji
- [x] `overflow-x: clip` on `html`/`body`; layouts designed for a 900px minimum window width (verified in the screenshots listed in the release report)
- [x] Severity/confidence conveyed by text as well as colour
