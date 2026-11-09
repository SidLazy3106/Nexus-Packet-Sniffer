import type { ComponentType, ReactNode } from 'react'
import { fmtInt } from '../lib/format'
import { SEVERITY_RANK } from '../lib/groupFindings'
import { C, tint } from '../lib/palette'
import type { Confidence, Severity } from '../lib/types'

export const SEVERITY_STYLE: Record<Severity, { color: string; bg: string; rank: number }> = {
  Informational: { color: C.dim, bg: tint(C.dim, 12), rank: SEVERITY_RANK.Informational },
  Low: { color: C.celadon, bg: tint(C.celadon, 14), rank: SEVERITY_RANK.Low },
  Medium: { color: C.warn, bg: tint(C.warn, 15), rank: SEVERITY_RANK.Medium },
  High: { color: C.orange, bg: tint(C.orange, 16), rank: SEVERITY_RANK.High },
  Critical: { color: C.crit, bg: tint(C.crit, 18), rank: SEVERITY_RANK.Critical },
}

export const PROTO_COLOR: Record<string, string> = {
  TCP: C.accent,
  UDP: C.celadon,
  DNS: C.wisteria,
  DHCP: C.sand,
  ICMP: C.warn,
  ICMPv6: C.warn,
  ARP: C.ok,
  IPv4: C.faint,
  IPv6: C.faint,
  Ethernet: C.faint,
}
export const protoColor = (p: string) => PROTO_COLOR[p] ?? C.faint

export function Card({ children, className = '', pad = true }: { children: ReactNode; className?: string; pad?: boolean }) {
  return <section className={`card ${pad ? 'p-4' : ''} ${className}`}>{children}</section>
}

export function CardTitle({ icon: Icon, children, right }: { icon?: ComponentType<{ size?: number; className?: string }>; children: ReactNode; right?: ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 mb-3 min-w-0">
      <h3 className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-dim min-w-0">
        {Icon && <Icon size={14} className="text-faint shrink-0" />}
        <span className="truncate">{children}</span>
      </h3>
      {right}
    </div>
  )
}

export function Metric({ label, value, sub, icon: Icon, tone }: { label: string; value: ReactNode; sub?: ReactNode; icon?: ComponentType<{ size?: number; className?: string }>; tone?: string }) {
  return (
    <Card className="min-w-0">
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-dim truncate">{label}</div>
          <div className="mt-1.5 serif text-[28px] leading-8 num truncate" style={tone ? { color: tone } : undefined}>
            {value}
          </div>
          {sub && <div className="mt-1 text-xs text-faint truncate">{sub}</div>}
        </div>
        {Icon && (
          <div className="grid place-items-center size-8 rounded-lg bg-accent/10 text-accent shrink-0">
            <Icon size={16} />
          </div>
        )}
      </div>
    </Card>
  )
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const s = SEVERITY_STYLE[severity]
  return (
    <span className="inline-flex items-center gap-1.5 h-5 px-2 rounded-full text-[11px] font-semibold whitespace-nowrap" style={{ color: s.color, background: s.bg }}>
      <span className="size-1.5 rounded-full" style={{ background: s.color }} />
      {severity}
    </span>
  )
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  const tone = confidence === 'High' ? C.ok : confidence === 'Medium' ? C.warn : C.dim
  return (
    <span className="inline-flex items-center h-5 px-2 rounded-full text-[11px] font-medium whitespace-nowrap border" style={{ color: tone, borderColor: tint(tone, 40) }}>
      {confidence} confidence
    </span>
  )
}

export function ProtoChip({ protocol }: { protocol: string }) {
  const c = protoColor(protocol)
  return (
    <span className="inline-flex items-center h-[18px] px-1.5 rounded text-[11px] font-semibold kbd-mono" style={{ color: c, background: tint(c, 14) }}>
      {protocol}
    </span>
  )
}

export function Empty({ icon: Icon, title, children, action }: { icon?: ComponentType<{ size?: number; className?: string }>; title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="grid place-items-center text-center py-10 px-6">
      <div className="max-w-sm">
        {Icon && (
          <div className="mx-auto mb-3 grid place-items-center size-10 rounded-xl bg-raised border border-line text-faint">
            <Icon size={20} />
          </div>
        )}
        <div className="text-sm font-semibold text-ink">{title}</div>
        {children && <div className="mt-1.5 text-xs leading-5 text-dim">{children}</div>}
        {action && <div className="mt-4 flex justify-center gap-2">{action}</div>}
      </div>
    </div>
  )
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3 mb-4">
      <div className="min-w-0">
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        {subtitle && <p className="text-xs text-dim mt-0.5">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}

export function Bar({ value, color = C.accent }: { value: number; color?: string }) {
  return (
    <div className="h-1.5 rounded-full bg-line-soft overflow-hidden">
      <div className="h-full rounded-full transition-[width] duration-300" style={{ width: `${Math.max(0, Math.min(100, value))}%`, background: color }} />
    </div>
  )
}

export function Tabs<T extends string>({ value, onChange, items }: { value: T; onChange: (v: T) => void; items: { id: T; label: string; badge?: number }[] }) {
  return (
    <div className="inline-flex p-0.5 rounded-lg bg-surface border border-line" role="tablist">
      {items.map((it) => (
        <button
          key={it.id}
          role="tab"
          aria-selected={value === it.id}
          onClick={() => onChange(it.id)}
          className={`h-7 px-3 rounded-md text-xs font-medium cursor-pointer transition-colors ${value === it.id ? 'bg-accent/15 text-ink' : 'text-dim hover:text-ink'}`}
        >
          {it.label}
          {it.badge !== undefined && it.badge > 0 && <span className="ml-1.5 text-[10px] text-faint num">{it.badge}</span>}
        </button>
      ))}
    </div>
  )
}

/** One label/value line with a hairline underneath; used for counter lists. */
export function StatRow({ label, value, tone }: { label: string; value: ReactNode; tone?: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-line-soft pb-1.5 min-w-0">
      <dt className="text-dim truncate">{label}</dt>
      <dd className="num font-semibold" style={tone ? { color: tone } : undefined}>{typeof value === 'number' ? fmtInt(value) : value}</dd>
    </div>
  )
}

export function Mono({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <span className={`kbd-mono ${className}`}>{children}</span>
}
