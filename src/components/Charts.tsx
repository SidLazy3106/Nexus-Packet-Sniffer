import { Area, AreaChart, CartesianGrid, Cell, Pie, PieChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import type { Bucket, Count } from '../lib/types'
import { fmtBytes, fmtInt, fmtRate } from '../lib/format'
import { C } from '../lib/palette'
import { protoColor } from './ui'

const AXIS = { fontSize: 11, fill: C.faint }
const TIP = {
  contentStyle: { background: C.surface, border: `1px solid ${C.line}`, borderRadius: 6, fontSize: 12, color: C.ink },
  labelStyle: { color: C.dim },
  itemStyle: { color: C.ink },
}

function clock(sec: number): string {
  const d = new Date(sec * 1000)
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`
}

export type SeriesKind = 'bandwidth' | 'packets'

/** Area chart over per-second buckets. Values come only from captured packets; no smoothing. */
export function TrafficChart({ series, kind, height = 200 }: { series: Bucket[]; kind: SeriesKind; height?: number }) {
  const color = kind === 'bandwidth' ? C.accent : C.celadon
  const data = series.map((b) => ({ t: b.sec, v: kind === 'bandwidth' ? b.bytes * 8 : b.packets }))
  const fmt = (v: number) => (kind === 'bandwidth' ? fmtRate(v / 8) : `${fmtInt(v)} pkt/s`)
  const id = `g-${kind}`
  return (
    <div style={{ height }} className="min-w-0">
      <ResponsiveContainer width="100%" height="100%" minWidth={0}>
        <AreaChart data={data} margin={{ top: 6, right: 8, left: 0, bottom: 0 }}>
          <defs>
            <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={color} stopOpacity={0.28} />
              <stop offset="100%" stopColor={color} stopOpacity={0.01} />
            </linearGradient>
          </defs>
          <CartesianGrid stroke={C.lineSoft} strokeDasharray="2 6" vertical={false} />
          <XAxis dataKey="t" tickFormatter={clock} tick={AXIS} axisLine={false} tickLine={false} minTickGap={48} />
          <YAxis tickFormatter={(v: number) => (kind === 'bandwidth' ? fmtRate(v / 8).replace(/\.\d+/, '') : fmtInt(v))} tick={AXIS} axisLine={false} tickLine={false} width={64} allowDecimals={false} />
          <Tooltip {...TIP} labelFormatter={(t) => clock(Number(t))} formatter={(v) => [fmt(Number(v)), kind === 'bandwidth' ? 'Throughput' : 'Packets']} />
          <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.75} fill={`url(#${id})`} isAnimationActive={false} dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

export function ProtocolDonut({ protocols, total }: { protocols: Count[]; total: number }) {
  const data = protocols.slice(0, 8).map((p) => ({ name: p.name, value: p.packets }))
  const rest = total - data.reduce((a, d) => a + d.value, 0)
  if (rest > 0) data.push({ name: 'Other', value: rest })
  return (
    <div className="flex items-center gap-4 min-w-0">
      <div className="size-[140px] shrink-0">
        <ResponsiveContainer width="100%" height="100%" minWidth={0}>
          <PieChart>
            <Pie data={data} dataKey="value" innerRadius={44} outerRadius={66} paddingAngle={1.5} stroke="none" isAnimationActive={false}>
              {data.map((d) => (
                <Cell key={d.name} fill={protoColor(d.name)} />
              ))}
            </Pie>
            <Tooltip {...TIP} formatter={(v, n) => [`${fmtInt(Number(v))} packets`, String(n)]} />
          </PieChart>
        </ResponsiveContainer>
      </div>
      <ul className="min-w-0 flex-1 space-y-1.5">
        {data.map((d) => (
          <li key={d.name} className="flex items-center gap-2 text-xs min-w-0">
            <span className="size-2 rounded-sm shrink-0" style={{ background: protoColor(d.name) }} />
            <span className="truncate flex-1">{d.name}</span>
            <span className="num text-dim">{total > 0 ? ((d.value / total) * 100).toFixed(1) : '0'}%</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export function TopList({ items, empty }: { items: Count[]; empty: string }) {
  if (items.length === 0) return <div className="text-xs text-faint py-3">{empty}</div>
  const max = Math.max(...items.map((i) => i.bytes), 1)
  return (
    <ul className="space-y-2">
      {items.map((i) => (
        <li key={i.name} className="min-w-0">
          <div className="flex items-baseline justify-between gap-3 text-xs">
            <span className="kbd-mono truncate">{i.name}</span>
            <span className="num text-dim shrink-0">
              {fmtBytes(i.bytes)} · {fmtInt(i.packets)} pkts
            </span>
          </div>
          <div className="mt-1 h-1 rounded-full bg-line-soft overflow-hidden">
            <div className="h-full rounded-full bg-accent/70" style={{ width: `${(i.bytes / max) * 100}%` }} />
          </div>
        </li>
      ))}
    </ul>
  )
}
