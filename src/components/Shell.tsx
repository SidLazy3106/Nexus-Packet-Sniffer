import { Activity, AlertTriangle, BarChart3, Cpu, Copy, Gauge, History, Layers, LayoutDashboard, Radio, Search, Settings as Cog, Stethoscope, X } from 'lucide-react'
import { useGSAP } from '@gsap/react'
import gsap from 'gsap'
import { useRef } from 'react'
import type { ComponentType } from 'react'
import { dismissToast, setPage, useApp } from '../lib/store'
import type { PageId } from '../lib/store'
import { notify } from '../lib/store'
import { C, tint } from '../lib/palette'

export const NAV: { id: PageId; label: string; icon: ComponentType<{ size?: number; className?: string }> }[] = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'capture', label: 'Live Capture', icon: Radio },
  { id: 'explorer', label: 'Packet Explorer', icon: Search },
  { id: 'protocols', label: 'Protocol Analysis', icon: Layers },
  { id: 'rca', label: 'Root Cause Analysis', icon: Stethoscope },
  { id: 'analytics', label: 'Traffic Analytics', icon: BarChart3 },
  { id: 'sessions', label: 'Capture Sessions', icon: History },
  { id: 'settings', label: 'Settings', icon: Cog },
]

/** An ensō: one brushstroke circle, left deliberately unclosed. Draws itself once on load. */
export function Logo({ size = 22 }: { size?: number }) {
  const ref = useRef<SVGSVGElement>(null)
  useGSAP(
    () => {
      const mm = gsap.matchMedia()
      mm.add('(prefers-reduced-motion: no-preference)', () => {
        gsap.from('.enso-stroke', { strokeDashoffset: 80, duration: 1.1, ease: 'power1.out', stagger: 0.12 })
      })
      return () => mm.revert()
    },
    { scope: ref },
  )
  return (
    <svg ref={ref} width={size} height={size} viewBox="0 0 32 32" aria-hidden fill="none" stroke={C.ink} strokeLinecap="round">
      <path className="enso-stroke" d="M24.6 9.4A10.2 10.2 0 1 0 26 17" strokeWidth="2.6" strokeDasharray="80" />
      <path className="enso-stroke" d="M23.8 8.4A11 11 0 0 0 9 6.6" strokeWidth="1.1" strokeDasharray="80" opacity=".55" />
    </svg>
  )
}

export function Sidebar() {
  const page = useApp((s) => s.page)
  const findings = useApp((s) => s.snapshot?.diagnostics.findings)
  const issues = findings?.filter((f) => f.category !== 'capture' && f.severity !== 'Informational').length ?? 0
  return (
    <nav className="flex flex-col gap-0.5 p-2 border-r border-line bg-surface/70 w-[228px] max-[1100px]:w-[58px] shrink-0 transition-[width] duration-200" aria-label="Main navigation">
      {NAV.map(({ id, label, icon: Icon }) => {
        const active = page === id
        return (
          <button
            key={id}
            onClick={() => setPage(id)}
            aria-current={active ? 'page' : undefined}
            title={label}
            className={`relative flex items-center gap-3 h-9 px-3 rounded-lg text-[13px] cursor-pointer transition-colors max-[1100px]:justify-center max-[1100px]:px-0 ${active ? 'bg-accent/15 text-ink' : 'text-dim hover:text-ink hover:bg-white/[0.04]'}`}
          >
            {active && <span className="absolute left-0 top-2.5 bottom-2.5 w-px bg-warn" />}
            <Icon size={17} className={active ? 'text-warn' : ''} />
            <span className="max-[1100px]:hidden truncate">{label}</span>
            {id === 'rca' && issues > 0 && (
              <span className="ml-auto max-[1100px]:hidden num text-[10px] font-semibold px-1.5 rounded-full bg-warn/20 text-warn">{issues}</span>
            )}
          </button>
        )
      })}
    </nav>
  )
}

export function StatusPill() {
  const snap = useApp((s) => s.snapshot)
  const st = snap?.capture.status ?? 'idle'
  let text = 'Idle'
  let color: string = C.faint
  let pulse = false
  if (snap?.importing) { text = 'Importing'; color = C.celadon; pulse = true }
  else if (st === 'capturing') { text = 'Capturing'; color = C.ok; pulse = true }
  else if (st === 'paused') { text = 'Paused'; color = C.warn }
  else if (st === 'error') { text = 'Capture error'; color = C.crit }
  else if (snap?.source.kind === 'file') { text = 'File loaded'; color = C.accent }
  else if (st === 'stopped') { text = 'Stopped'; color = C.dim }
  return (
    <span className="inline-flex items-center gap-2 h-7 px-3 rounded-full border border-line bg-surface text-xs font-medium" role="status">
      <span className={`size-2 rounded-full ${pulse ? 'pulse' : ''}`} style={{ background: color }} />
      {text}
    </span>
  )
}

export function TopBar() {
  const snap = useApp((s) => s.snapshot)
  const ifaces = useApp((s) => s.interfaces)
  const name = useApp((s) => s.ifaceName)
  const iface = ifaces.find((i) => i.name === name)
  const label = snap?.source.kind === 'file' ? `File: ${snap.source.name}` : (iface?.friendly_name ?? 'No interface selected')
  return (
    <header className="h-12 shrink-0 flex items-center gap-4 px-4 border-b border-line bg-surface/90 backdrop-blur">
      <div className="flex items-center gap-2.5 min-w-0">
        <Logo />
        <span className="font-semibold tracking-[0.14em] text-[13px]">NEXUS</span>
        <span className="text-faint text-xs max-[900px]:hidden">Network Packet Analyzer</span>
      </div>
      <div className="flex items-center gap-2 min-w-0 text-xs text-dim border-l border-line pl-4">
        <Radio size={14} className="text-faint shrink-0" />
        <span className="truncate max-w-[280px]" title={label}>{label}</span>
      </div>
      <div className="ml-auto flex items-center gap-3">
        {snap && (
          <div className="flex items-center gap-3 text-xs text-dim max-[860px]:hidden" title="Resource use of the NEXUS process">
            <span className="inline-flex items-center gap-1.5 num"><Cpu size={13} className="text-faint" />{snap.system.cpu_percent.toFixed(1)}%</span>
            <span className="inline-flex items-center gap-1.5 num"><Gauge size={13} className="text-faint" />{snap.system.memory_mb.toFixed(0)} MB</span>
          </div>
        )}
        <StatusPill />
        <button className="btn !px-2" onClick={() => setPage('settings')} aria-label="Open settings" title="Settings">
          <Cog size={15} />
        </button>
      </div>
    </header>
  )
}

export function NpcapBanner() {
  const info = useApp((s) => s.appInfo)
  if (!info || info.npcap.available) return null
  const copy = () => navigator.clipboard?.writeText(info.npcap.download_url).then(() => notify('info', 'Link copied.'), () => notify('error', 'Could not copy the link.'))
  return (
    <div className="mx-4 mt-4 rounded-lg border border-warn/40 bg-warn/[0.08] p-3.5 text-xs flex gap-3" role="alert">
      <AlertTriangle size={18} className="text-warn shrink-0 mt-0.5" />
      <div className="min-w-0 space-y-1.5">
        <div className="font-semibold text-sm text-warn">Npcap is not installed - live capture is unavailable</div>
        <p className="text-ink/90 leading-5">{info.npcap.detail}</p>
        <p className="text-dim leading-5">{info.npcap.admin_note}</p>
        <p className="text-dim leading-5">You can still import and analyse existing PCAP/PCAPNG files without Npcap.</p>
        <div className="flex items-center gap-2 pt-1">
          <span className="kbd-mono text-celadon">{info.npcap.download_url}</span>
          <button className="btn !h-6 !px-2 text-[11px]" onClick={copy}><Copy size={12} />Copy link</button>
        </div>
      </div>
    </div>
  )
}

export function Toasts() {
  const toasts = useApp((s) => s.toasts)
  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 w-[min(420px,calc(100vw-2rem))]" aria-live="polite">
      {toasts.map((t) => {
        const c = t.kind === 'error' ? C.crit : t.kind === 'success' ? C.ok : C.accent
        return (
          <div key={t.id} className="flex items-start gap-2.5 rounded-lg border bg-raised p-3 text-xs shadow-lg shadow-black/40" style={{ borderColor: tint(c, 45) }} role={t.kind === 'error' ? 'alert' : 'status'}>
            <Activity size={14} style={{ color: c }} className="mt-0.5 shrink-0" />
            <span className="flex-1 leading-5 break-words min-w-0">{t.text}</span>
            <button onClick={() => dismissToast(t.id)} className="text-faint hover:text-ink cursor-pointer" aria-label="Dismiss"><X size={14} /></button>
          </div>
        )
      })}
    </div>
  )
}
