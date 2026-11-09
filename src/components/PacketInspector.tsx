import { useEffect, useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Info, TriangleAlert } from 'lucide-react'
import { api, errorText } from '../lib/api'
import { explainField } from '../lib/explain'
import { fmtBytes } from '../lib/format'
import type { PacketDetail } from '../lib/types'
import { Empty, Mono, ProtoChip } from './ui'

interface Sel { layer: string; name: string; offset: number; len: number }

const MAX_HEX_BYTES = 8192

function HexView({ detail, sel, layerRange }: { detail: PacketDetail; sel: Sel | null; layerRange: [number, number] | null }) {
  const tokens = useMemo(() => detail.hex.match(/.{2}/g) ?? [], [detail.hex])
  const shown = Math.min(tokens.length, MAX_HEX_BYTES)
  const rows: number[] = []
  for (let i = 0; i < shown; i += 16) rows.push(i)
  const inSel = (i: number) => sel !== null && i >= sel.offset && i < sel.offset + sel.len
  const inLayer = (i: number) => layerRange !== null && i >= layerRange[0] && i < layerRange[1]
  const cls = (i: number) =>
    inSel(i) ? 'bg-accent text-white rounded-[3px]' : inLayer(i) ? 'bg-accent/15 rounded-[3px]' : i >= detail.payload_offset ? 'text-celadon/90' : ''
  return (
    <div className="kbd-mono text-[12px] leading-[19px] overflow-auto" aria-label="Hexadecimal packet bytes">
      {rows.map((start) => {
        const slice = tokens.slice(start, start + 16)
        return (
          <div key={start} className="flex gap-4 whitespace-pre">
            <span className="text-faint select-none w-[44px]">{start.toString(16).padStart(4, '0')}</span>
            <span className="flex">
              {slice.map((t, k) => (
                <span key={k} className={`px-[2.5px] ${k === 8 ? 'ml-2' : ''} ${cls(start + k)}`}>
                  {t === '**' ? '··' : t}
                </span>
              ))}
              {Array.from({ length: 16 - slice.length }).map((_, k) => (
                <span key={`p${k}`} className={`px-[2.5px] ${slice.length + k === 8 ? 'ml-2' : ''}`}>{'  '}</span>
              ))}
            </span>
            <span className="text-dim">
              {slice.map((t, k) => {
                const b = t === '**' ? -1 : parseInt(t, 16)
                const ch = b === -1 ? '·' : b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.'
                return (
                  <span key={k} className={cls(start + k)}>
                    {ch}
                  </span>
                )
              })}
            </span>
          </div>
        )
      })}
      {tokens.length > shown && <div className="text-faint mt-2">… {tokens.length - shown} more bytes not shown</div>}
    </div>
  )
}

export function PacketInspector({ no }: { no: number | null }) {
  const [detail, setDetail] = useState<PacketDetail | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [sel, setSel] = useState<Sel | null>(null)
  const [collapsed, setCollapsed] = useState<ReadonlySet<string>>(new Set())

  useEffect(() => {
    let live = true
    setSel(null)
    if (no == null) {
      setDetail(null)
      setErr(null)
      return
    }
    api
      .getPacket(no)
      .then((d) => {
        if (!live) return
        setDetail(d)
        setErr(d ? null : 'This packet is no longer in memory (the retention limit removed it).')
      })
      .catch((e) => live && setErr(errorText(e)))
    return () => {
      live = false
    }
  }, [no])

  if (no == null) return <Empty icon={Info} title="No packet selected">Select a packet in the table to see its decoded headers and raw bytes.</Empty>
  if (err) return <Empty icon={TriangleAlert} title="Packet unavailable">{err}</Empty>
  if (!detail) return <div className="p-6 text-xs text-faint">Loading packet {no}…</div>

  const layerRange: [number, number] | null = sel ? (() => {
    const l = detail.layers.find((x) => x.name === sel.layer)
    return l ? [l.offset, l.offset + l.len] : null
  })() : null
  const explanation = sel ? explainField(sel.layer, sel.name) : null
  const r = detail.row
  const toggle = (name: string) => {
    const n = new Set(collapsed)
    if (n.has(name)) n.delete(name)
    else n.add(name)
    setCollapsed(n)
  }

  return (
    <div className="grid gap-4 xl:grid-cols-[minmax(320px,5fr)_minmax(420px,6fr)] min-w-0 p-4">
      <div className="min-w-0 space-y-3">
        <div className="rounded-lg border border-line bg-surface/60 p-3 text-xs space-y-1.5">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold">Packet {r.no}</span>
            <ProtoChip protocol={r.protocol} />
            <span className="text-faint">{new Date(r.ts_us / 1000).toISOString().replace('T', ' ').replace('Z', ' UTC')}</span>
          </div>
          <div className="text-dim">
            {detail.captured_len} bytes captured of {detail.original_len} on the wire ({fmtBytes(detail.original_len)})
            {detail.cut_by_retention && <span className="text-warn"> · payload shortened by the retention setting</span>}
          </div>
          <div className="text-dim">
            Payload starts at byte {detail.payload_offset}: <Mono className="text-celadon/90 break-all">{detail.payload_preview}</Mono>
          </div>
          {detail.redacted && <div className="text-warn">Payload bytes are masked by the privacy setting.</div>}
        </div>

        {detail.anomalies.length > 0 && (
          <div className="rounded-lg border border-crit/40 bg-crit/[0.07] p-3 text-xs space-y-1" role="alert">
            <div className="flex items-center gap-1.5 font-semibold text-crit"><TriangleAlert size={13} /> Protocol anomalies</div>
            {detail.anomalies.map((a, i) => (
              <div key={i} className="text-ink/90"><span className="text-dim">{a.layer}:</span> {a.detail}</div>
            ))}
          </div>
        )}

        <div className="rounded-lg border border-line overflow-hidden">
          {detail.layers.map((l) => {
            const open = !collapsed.has(l.name)
            return (
              <div key={l.name + l.offset} className="border-b border-line-soft last:border-0">
                <button
                  className={`w-full flex items-center gap-1.5 px-2.5 h-8 text-left cursor-pointer hover:bg-white/[0.03] ${sel?.layer === l.name && sel.len === 0 ? 'bg-accent/10' : ''}`}
                  onClick={() => {
                    toggle(l.name)
                    setSel({ layer: l.name, name: l.name, offset: l.offset, len: l.len })
                  }}
                  aria-expanded={open}
                >
                  {open ? <ChevronDown size={14} className="text-faint" /> : <ChevronRight size={14} className="text-faint" />}
                  <span className="font-semibold text-xs">{l.name}</span>
                  <span className="text-faint text-[11px] ml-auto num">bytes {l.offset}–{l.offset + Math.max(0, l.len) - 1}</span>
                </button>
                {open && (
                  <ul className="pb-1.5">
                    {l.fields.map((f, i) => {
                      const active = sel?.layer === l.name && sel.name === f.name && sel.offset === f.offset
                      return (
                        <li key={i}>
                          <button
                            onClick={() => setSel({ layer: l.name, name: f.name, offset: f.offset, len: f.len })}
                            className={`w-full grid grid-cols-[minmax(110px,170px)_1fr] gap-3 pl-8 pr-3 py-[3px] text-left cursor-pointer text-xs hover:bg-white/[0.04] ${active ? 'bg-accent/20' : ''}`}
                          >
                            <span className="text-dim truncate">{f.name}</span>
                            <Mono className="break-all text-ink">{f.value}</Mono>
                          </button>
                        </li>
                      )
                    })}
                  </ul>
                )}
              </div>
            )
          })}
        </div>

        <div className="rounded-lg border border-line bg-surface/60 p-3 text-xs min-h-[64px]" aria-live="polite">
          {sel && explanation ? (
            <>
              <div className="font-semibold mb-1">{sel.layer} · {sel.name}</div>
              <p className="text-dim leading-5">{explanation}</p>
            </>
          ) : sel ? (
            <p className="text-dim">{sel.name} · bytes {sel.offset}–{sel.offset + sel.len - 1}</p>
          ) : (
            <p className="text-faint">Click a header or field to highlight its bytes and read what it means.</p>
          )}
        </div>
      </div>

      <div className="min-w-0 rounded-lg border border-line bg-surface p-3">
        <div className="text-[11px] font-semibold uppercase tracking-wide text-faint mb-2">Raw bytes</div>
        <HexView detail={detail} sel={sel} layerRange={layerRange} />
      </div>
    </div>
  )
}
