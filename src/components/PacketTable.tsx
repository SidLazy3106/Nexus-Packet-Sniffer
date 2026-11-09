import { memo, useEffect, useRef } from 'react'
import type { MouseEvent } from 'react'
import { useVirtualizer } from '@tanstack/react-virtual'
import { ArrowDown, ArrowUp, TriangleAlert } from 'lucide-react'
import type { PacketRow } from '../lib/types'
import { endpoint, fmtTime } from '../lib/format'
import type { Sort, SortKey } from '../lib/useRows'
import { PACKET_ROW_HEIGHT as ROW_H } from '../lib/constants'
import { protoColor } from './ui'

const COLS = '60px 102px minmax(130px,1.1fr) minmax(130px,1.1fr) 72px 64px minmax(200px,3fr)'
const COLS_COMPACT = '56px minmax(110px,1fr) 62px 56px'

interface Props {
  rows: PacketRow[]
  selectedNo: number | null
  checked: ReadonlySet<number>
  onSelect: (no: number, e: MouseEvent) => void
  autoScroll: boolean
  sort: Sort
  onSort: (k: SortKey) => void
  compact?: boolean
  focusNo?: number | null
  emptyHint: React.ReactNode
}

const Row = memo(function Row({ r, selected, checked, compact, top, onSelect }: { r: PacketRow; selected: boolean; checked: boolean; compact: boolean; top: number; onSelect: (no: number, e: MouseEvent) => void }) {
  const c = protoColor(r.protocol)
  return (
    <div
      role="row"
      aria-selected={selected}
      onClick={(e) => onSelect(r.no, e)}
      className={`absolute left-0 right-0 grid items-center gap-x-3 px-3 cursor-pointer kbd-mono text-[12px] border-b border-line-soft/60 hover:bg-white/[0.035] ${selected ? 'bg-accent/20 hover:bg-accent/25' : checked ? 'bg-accent/10' : r.anomaly ? 'bg-crit/[0.07]' : ''}`}
      style={{ height: ROW_H, transform: `translateY(${top}px)`, gridTemplateColumns: compact ? COLS_COMPACT : COLS, boxShadow: `inset 2px 0 0 ${c}` }}
    >
      <span className="text-faint num text-right">{r.no}</span>
      {!compact && <span className="text-dim num truncate">{fmtTime(r.ts_us)}</span>}
      {compact ? (
        <span className="truncate" title={`${endpoint(r.src, r.sport)} → ${endpoint(r.dst, r.dport)}`}>{r.src} → {r.dst}</span>
      ) : (
        <>
          <span className="truncate" title={endpoint(r.src, r.sport)}>{endpoint(r.src, r.sport)}</span>
          <span className="truncate" title={endpoint(r.dst, r.dport)}>{endpoint(r.dst, r.dport)}</span>
        </>
      )}
      <span className="font-semibold truncate flex items-center gap-1" style={{ color: c }}>
        {r.anomaly && <TriangleAlert size={11} className="text-crit shrink-0" aria-label="Anomaly" />}
        {r.protocol}
      </span>
      <span className="text-dim num text-right">{r.length}</span>
      {!compact && <span className="truncate text-ink/85" title={r.info}>{r.info}</span>}
    </div>
  )
})

export function PacketTable({ rows, selectedNo, checked, onSelect, autoScroll, sort, onSort, compact = false, focusNo, emptyHint }: Props) {
  const parent = useRef<HTMLDivElement>(null)
  const v = useVirtualizer({ count: rows.length, getScrollElement: () => parent.current, estimateSize: () => ROW_H, overscan: 24 })

  useEffect(() => {
    if (autoScroll && rows.length > 0 && sort.key !== 'length' && sort.dir === 1) v.scrollToIndex(rows.length - 1, { align: 'end' })
  }, [autoScroll, rows.length, v, sort])

  useEffect(() => {
    if (focusNo == null) return
    // Rows are ordered by number when sorted ascending; otherwise fall back to a linear search.
    const idx = rows.findIndex((r) => r.no === focusNo)
    if (idx >= 0) v.scrollToIndex(idx, { align: 'center' })
  }, [focusNo, rows, v])

  const head = (label: string, key?: SortKey, align = '') => {
    const active = key && sort.key === key
    const Arrow = sort.dir === 1 ? ArrowUp : ArrowDown
    return key ? (
      <button className={`flex items-center gap-1 cursor-pointer hover:text-ink ${align} ${active ? 'text-ink' : ''}`} onClick={() => onSort(key)} aria-label={`Sort by ${label}`}>
        {label}
        {active && <Arrow size={11} />}
      </button>
    ) : (
      <span className={align}>{label}</span>
    )
  }

  return (
    <div className="flex flex-col min-h-0 h-full rounded-lg border border-line bg-surface overflow-hidden">
      <div className="overflow-x-auto flex-1 min-h-0 flex flex-col">
        <div className={compact ? 'min-w-[320px]' : 'min-w-[880px]'} style={{ display: 'flex', flexDirection: 'column', minHeight: 0, flex: 1 }}>
          <div className="grid gap-x-3 px-3 h-7 items-center text-[11px] font-semibold uppercase tracking-wide text-faint bg-raised border-b border-line shrink-0" style={{ gridTemplateColumns: compact ? COLS_COMPACT : COLS }} role="row">
            {head('No.', 'no', 'justify-end')}
            {!compact && head('Time', 'time')}
            {compact ? head('Source → Dest') : <>{head('Source')}{head('Destination')}</>}
            {head('Proto')}
            {head('Len', 'length', 'justify-end')}
            {!compact && head('Information')}
          </div>
          <div ref={parent} className="flex-1 min-h-0 overflow-y-auto overflow-x-hidden" role="grid" aria-rowcount={rows.length}>
            {rows.length === 0 ? (
              <div className="h-full grid place-items-center p-6 text-center text-xs text-dim">{emptyHint}</div>
            ) : (
              <div style={{ height: v.getTotalSize(), position: 'relative' }}>
                {v.getVirtualItems().map((vi) => {
                  const r = rows[vi.index]
                  return <Row key={r.no} r={r} top={vi.start} compact={compact} selected={r.no === selectedNo} checked={checked.has(r.no)} onSelect={onSelect} />
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
