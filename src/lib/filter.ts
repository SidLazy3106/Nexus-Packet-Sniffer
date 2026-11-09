import type { PacketRow } from './types'

/**
 * Client-side display filter. Space-separated terms are ANDed; each term is matched against
 * protocol, addresses, ports and the info column. `-term` excludes. `port:443`, `ip:10.0.0.1`,
 * `proto:tcp` target a single field.
 */
export function matchesFilter(row: PacketRow, terms: string[], protocols: ReadonlySet<string>): boolean {
  if (protocols.size > 0 && !protocols.has(row.protocol)) return false
  for (const raw of terms) {
    const negate = raw.startsWith('-') && raw.length > 1
    const t = (negate ? raw.slice(1) : raw).toLowerCase()
    const hit = termHit(row, t)
    if (negate ? hit : !hit) return false
  }
  return true
}

function termHit(row: PacketRow, t: string): boolean {
  const m = /^(port|ip|src|dst|proto):(.*)$/.exec(t)
  const key = m ? m[1] : ''
  const val = m ? m[2] : t
  switch (key) {
    case 'port':
      return String(row.sport) === val || String(row.dport) === val
    case 'ip':
      return row.src.toLowerCase() === val || row.dst.toLowerCase() === val
    case 'src':
      return row.src.toLowerCase().includes(val)
    case 'dst':
      return row.dst.toLowerCase().includes(val)
    case 'proto':
      return row.protocol.toLowerCase() === val
    case '':
      return (
        row.protocol.toLowerCase().includes(val) ||
        row.src.toLowerCase().includes(val) ||
        row.dst.toLowerCase().includes(val) ||
        row.info.toLowerCase().includes(val) ||
        String(row.sport) === val ||
        String(row.dport) === val
      )
    default:
      return false
  }
}

export function parseTerms(text: string): string[] {
  return text.split(/\s+/).filter(Boolean)
}
