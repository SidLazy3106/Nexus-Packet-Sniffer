// Colours are defined once, as CSS tokens in index.css. Scripts reference them by name so
// charts, badges and inline styles follow the active theme with no literal colours in code.

export const C = {
  accent: 'var(--c-accent)',
  celadon: 'var(--c-celadon)',
  ok: 'var(--c-ok)',
  warn: 'var(--c-warn)',
  orange: 'var(--c-orange)',
  crit: 'var(--c-crit)',
  wisteria: 'var(--c-wisteria)',
  sand: 'var(--c-sand)',
  ink: 'var(--c-ink)',
  dim: 'var(--c-dim)',
  faint: 'var(--c-faint)',
  line: 'var(--c-line)',
  lineSoft: 'var(--c-line-soft)',
  surface: 'var(--c-surface)',
  raised: 'var(--c-raised)',
} as const

/** A colour at `pct` percent strength over transparent (for badge backgrounds and borders). */
export const tint = (color: string, pct = 14): string => `color-mix(in srgb, ${color} ${pct}%, transparent)`

export const HEALTH_TONE: Record<string, string> = {
  Healthy: C.ok,
  Fair: C.celadon,
  Degraded: C.warn,
  Poor: C.crit,
}
