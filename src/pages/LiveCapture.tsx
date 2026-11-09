import { useEffect, useMemo, useState } from 'react'
import type { MouseEvent } from 'react'
import { Download, FileUp, Pause, Play, RefreshCw, Search, Square, Trash2, Radio, ArrowDownToLine } from 'lucide-react'
import { PacketInspector } from '../components/PacketInspector'
import { PacketTable } from '../components/PacketTable'
import { Empty, PageHeader, protoColor } from '../components/ui'
import { api, errorText } from '../lib/api'
import { BPF_DEBOUNCE_MS } from '../lib/constants'
import { fmtBytes, fmtInt } from '../lib/format'
import { C, tint } from '../lib/palette'
import { parseTerms } from '../lib/filter'
import {
  clearCapture, exportCapture, importFile, pauseCapture, refreshInterfaces, resumeCapture, selectPacket, setBpf, setChecked,
  setIface, startCapture, stopCapture, useApp, usePackets,
} from '../lib/store'
import type { Sort, SortKey } from '../lib/useRows'
import { useViewRows } from '../lib/useRows'

export default function LiveCapture() {
  const { rows, version } = usePackets()
  const snap = useApp((s) => s.snapshot)
  const ifaces = useApp((s) => s.interfaces)
  const ifaceErr = useApp((s) => s.interfacesError)
  const ifaceLoading = useApp((s) => s.interfacesLoading)
  const ifaceName = useApp((s) => s.ifaceName)
  const bpf = useApp((s) => s.bpfFilter)
  const selectedNo = useApp((s) => s.selectedNo)
  const checked = useApp((s) => s.checked)
  const busy = useApp((s) => s.busy)
  const npcapOk = useApp((s) => s.appInfo?.npcap.available ?? true)

  const [display, setDisplay] = useState('')
  const [protos, setProtos] = useState<ReadonlySet<string>>(new Set())
  const [autoScroll, setAutoScroll] = useState(true)
  const [sort, setSort] = useState<Sort>({ key: 'no', dir: 1 })
  const [bpfError, setBpfError] = useState<string | null>(null)
  const [anchor, setAnchor] = useState<number | null>(null)

  const capturing = snap?.capture.status === 'capturing' || snap?.capture.status === 'paused'
  const paused = snap?.capture.status === 'paused'
  const terms = useMemo(() => parseTerms(display), [display])
  const view = useViewRows(rows, version, terms, protos, sort)

  // Protocols present in the capture, for the quick-filter chips.
  const present = useMemo(() => (snap?.analytics.protocols ?? []).map((p) => p.name), [snap?.analytics.protocols])

  useEffect(() => {
    if (!bpf.trim()) return setBpfError(null)
    const t = setTimeout(() => {
      api.validateFilter(bpf).then(() => setBpfError(null), (e) => setBpfError(errorText(e)))
    }, BPF_DEBOUNCE_MS)
    return () => clearTimeout(t)
  }, [bpf])

  const onSelect = (no: number, e: MouseEvent) => {
    if (e.shiftKey && anchor !== null) {
      const [lo, hi] = [Math.min(anchor, no), Math.max(anchor, no)]
      setChecked(new Set(view.filter((r) => r.no >= lo && r.no <= hi).map((r) => r.no)))
    } else if (e.ctrlKey || e.metaKey) {
      const n = new Set(checked)
      if (n.has(no)) n.delete(no)
      else n.add(no)
      setChecked(n)
      setAnchor(no)
    } else {
      setAnchor(no)
      if (checked.size) setChecked(new Set())
    }
    selectPacket(no)
  }

  const onSort = (k: SortKey) => {
    setSort((s) => (s.key === k ? { key: k, dir: (s.dir * -1) as 1 | -1 } : { key: k, dir: 1 }))
    if (k === 'length') setAutoScroll(false)
  }

  const toggleProto = (p: string) => {
    const n = new Set(protos)
    if (n.has(p)) n.delete(p)
    else n.add(p)
    setProtos(n)
  }

  const a = snap?.analytics
  const c = snap?.capture
  const dropped = (c?.kernel_dropped ?? 0) + (c?.interface_dropped ?? 0)

  return (
    <div className="flex flex-col h-full min-h-0 gap-3">
      <PageHeader
        title="Live Capture"
        subtitle="Capture only networks you are authorised to monitor. While paused, packets are read and discarded (not buffered)."
        actions={
          <>
            <button className="btn" onClick={() => importFile()} disabled={busy || capturing}><FileUp size={14} />Import PCAP</button>
            <button className="btn" onClick={() => exportCapture(checked.size ? [...checked] : null)} disabled={busy || rows.length === 0}>
              <Download size={14} />Export {checked.size ? `${checked.size} selected` : 'all'}
            </button>
            <button className="btn" onClick={clearCapture} disabled={busy || capturing || rows.length === 0}><Trash2 size={14} />Clear</button>
          </>
        }
      />

      <div className="card p-3 flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-2 min-w-0">
          <span className="text-[11px] uppercase tracking-wide text-faint">Interface</span>
          <select className="input w-[min(320px,38vw)]" value={ifaceName ?? ''} onChange={(e) => setIface(e.target.value || null)} disabled={capturing} aria-label="Network interface">
            {ifaces.length === 0 && <option value="">{ifaceLoading ? 'Loading…' : 'No interfaces found'}</option>}
            {ifaces.map((i) => (
              <option key={i.name} value={i.name}>
                {i.friendly_name}{i.ipv4[0] ? ` · ${i.ipv4[0]}` : ''}{i.status === 'down' ? ' (disconnected)' : ''}{i.loopback ? ' (loopback)' : ''}
              </option>
            ))}
          </select>
        </label>
        <button className="btn !px-2" onClick={refreshInterfaces} disabled={capturing || ifaceLoading} aria-label="Refresh interfaces" title="Refresh interfaces"><RefreshCw size={14} className={ifaceLoading ? 'animate-spin' : ''} /></button>
        <label className="flex items-center gap-2 flex-1 min-w-[220px]">
          <span className="text-[11px] uppercase tracking-wide text-faint">BPF</span>
          <input className={`input flex-1 kbd-mono ${bpfError ? '!border-crit' : ''}`} placeholder="Capture filter, e.g. tcp port 443 or host 10.0.0.5" value={bpf} onChange={(e) => setBpf(e.target.value)} disabled={capturing} spellCheck={false} aria-label="BPF capture filter" aria-invalid={!!bpfError} />
        </label>
        <div className="flex items-center gap-2">
          {!capturing ? (
            <button className="btn btn-primary" onClick={startCapture} disabled={busy || !ifaceName || !npcapOk || !!bpfError}><Play size={14} />Start</button>
          ) : (
            <>
              {paused ? (
                <button className="btn" onClick={resumeCapture} disabled={busy}><Play size={14} />Resume</button>
              ) : (
                <button className="btn" onClick={pauseCapture} disabled={busy}><Pause size={14} />Pause</button>
              )}
              <button className="btn btn-danger" onClick={stopCapture} disabled={busy}><Square size={14} />Stop</button>
            </>
          )}
        </div>
        {bpfError && <div className="basis-full text-xs text-crit" role="alert">{bpfError}</div>}
        {ifaceErr && <div className="basis-full text-xs text-warn" role="alert">{ifaceErr}</div>}
        {c?.error && <div className="basis-full text-xs text-crit" role="alert">{c.error}</div>}
        {snap?.recording_note && <div className="basis-full text-xs text-warn">{snap.recording_note}</div>}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[220px] max-w-[460px]">
          <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
          <input className="input w-full !pl-8 kbd-mono" placeholder="Search IP, port, text · port:443 ip:10.0.0.1 -dns" value={display} onChange={(e) => setDisplay(e.target.value)} spellCheck={false} aria-label="Search packets" />
        </div>
        <div className="flex flex-wrap gap-1.5">
          {present.slice(0, 10).map((p) => {
            const on = protos.has(p)
            return (
              <button key={p} onClick={() => toggleProto(p)} aria-pressed={on} className="h-6 px-2 rounded-full text-[11px] font-semibold cursor-pointer border transition-colors" style={{ color: protoColor(p), borderColor: on ? protoColor(p) : C.line, background: on ? tint(protoColor(p), 16) : 'transparent' }}>
                {p}
              </button>
            )
          })}
          {(protos.size > 0 || display) && <button className="text-[11px] text-dim hover:text-ink cursor-pointer px-1" onClick={() => { setProtos(new Set()); setDisplay('') }}>Reset filters</button>}
        </div>
        <button className={`btn ml-auto ${autoScroll ? '!border-accent/60 !text-ink' : ''}`} onClick={() => setAutoScroll(!autoScroll)} aria-pressed={autoScroll}><ArrowDownToLine size={14} />Auto-scroll {autoScroll ? 'on' : 'off'}</button>
      </div>

      <div className="flex-1 min-h-[180px]">
        <PacketTable
          rows={view}
          selectedNo={selectedNo}
          checked={checked}
          onSelect={onSelect}
          autoScroll={autoScroll}
          sort={sort}
          onSort={onSort}
          emptyHint={
            rows.length > 0 ? (
              <span>No packets match the current filters.</span>
            ) : (
              <Empty icon={Radio} title={capturing ? 'Waiting for packets…' : 'No packets captured'}>
                {capturing ? 'The capture is running but no packets have matched yet.' : 'Choose an interface and press Start, or import a PCAP/PCAPNG file for offline analysis.'}
              </Empty>
            )
          }
        />
      </div>

      <div className="flex flex-wrap items-center gap-x-5 gap-y-1 text-[11px] text-dim num px-1">
        <span>Showing {fmtInt(view.length)} of {fmtInt(rows.length)} packets</span>
        <span>Traffic observed {fmtBytes(a?.total_bytes ?? 0)}</span>
        {checked.size > 0 && <span className="text-accent">{checked.size} selected</span>}
        <span title="Packets the capture driver dropped because the buffer overflowed (not network loss)" className={dropped > 0 ? 'text-warn' : ''}>Driver drops {fmtInt(dropped)}</span>
        <span title="Packets discarded because NEXUS' processing queue was full" className={(c?.pipeline_dropped ?? 0) > 0 ? 'text-warn' : ''}>Queue drops {fmtInt(c?.pipeline_dropped ?? 0)}</span>
        {(c?.paused_discarded ?? 0) > 0 && <span>Discarded while paused {fmtInt(c?.paused_discarded ?? 0)}</span>}
        {(snap?.evicted_packets ?? 0) > 0 && <span className="text-warn">{fmtInt(snap?.evicted_packets ?? 0)} oldest packets evicted by the retention limit</span>}
      </div>

      {selectedNo !== null && (
        <div className="card overflow-auto max-h-[38vh] shrink-0">
          <PacketInspector no={selectedNo} />
        </div>
      )}
    </div>
  )
}
