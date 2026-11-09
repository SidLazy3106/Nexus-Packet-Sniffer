import { useEffect, useMemo, useRef, useState } from 'react'
import type { PacketRow } from './types'
import { SORT_THROTTLE_MS } from './constants'
import { matchesFilter } from './filter'

export type SortKey = 'no' | 'time' | 'length'
export interface Sort { key: SortKey; dir: 1 | -1 }

interface Cache { sig: string; base: PacketRow[]; seen: number; firstNo: number }

/** Re-render at most once per `ms` while `active`, otherwise follow `value` immediately. */
function useThrottled(value: number, ms: number, active: boolean): number {
  const [v, setV] = useState(value)
  useEffect(() => {
    if (!active) return
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms, active])
  return active ? v : value
}

/**
 * Filtered + sorted view over the append-only packet array. Filtering is incremental (only
 * new rows are tested) and sorting that needs a full copy is throttled so a busy capture
 * cannot make the table recompute 60 times a second.
 */
export function useViewRows(rows: PacketRow[], version: number, terms: string[], protocols: ReadonlySet<string>, sort: Sort): PacketRow[] {
  const cache = useRef<Cache | null>(null)
  const needsCopy = !(sort.dir === 1 && (sort.key === 'no' || sort.key === 'time'))
  const effVersion = useThrottled(version, SORT_THROTTLE_MS, needsCopy)
  const sig = terms.join(' ') + '|' + [...protocols].sort().join(',')

  return useMemo(() => {
    void effVersion
    let base = rows
    if (terms.length > 0 || protocols.size > 0) {
      let c = cache.current
      const first = rows[0]?.no ?? 0
      if (!c || c.sig !== sig || rows.length < c.seen || c.firstNo !== first) {
        c = { sig, base: [], seen: 0, firstNo: first }
      }
      for (let i = c.seen; i < rows.length; i++) {
        if (matchesFilter(rows[i], terms, protocols)) c.base.push(rows[i])
      }
      c.seen = rows.length
      cache.current = c
      base = c.base
    } else {
      cache.current = null
    }
    if (!needsCopy) return base
    const copy = base.slice()
    const k = sort.key
    copy.sort((a, b) => (k === 'length' ? a.length - b.length : k === 'time' ? a.ts_us - b.ts_us : a.no - b.no) * sort.dir)
    return copy
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, effVersion, sig, needsCopy, sort.key, sort.dir])
}
