import type { Finding, Severity } from './types'

export const SEVERITY_RANK: Record<Severity, number> = { Informational: 0, Low: 1, Medium: 2, High: 3, Critical: 4 }

export interface FindingGroup {
  title: string
  /** Members ordered by severity (worst first), then most recent. */
  items: Finding[]
  /** Sum of occurrence counts across members. */
  total: number
}

/**
 * Group related findings (same title, typically one per flow or host) so one recurring condition
 * reads as one row. Groups are ordered by their worst member's severity.
 */
export function groupFindings(findings: readonly Finding[]): FindingGroup[] {
  const byTitle = new Map<string, Finding[]>()
  for (const f of findings) {
    const list = byTitle.get(f.title)
    if (list) list.push(f)
    else byTitle.set(f.title, [f])
  }
  return [...byTitle.entries()]
    .map(([title, items]) => ({
      title,
      items: [...items].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || b.last_ts_us - a.last_ts_us),
      total: items.reduce((sum, f) => sum + f.count, 0),
    }))
    .sort((a, b) => SEVERITY_RANK[b.items[0].severity] - SEVERITY_RANK[a.items[0].severity] || b.total - a.total)
}
