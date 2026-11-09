import { Activity, Network, Package, Radio, ShieldCheck, TriangleAlert, Waypoints } from 'lucide-react'
import { ProtocolDonut, TrafficChart } from '../components/Charts'
import { Card, CardTitle, Empty, Metric, PageHeader, SEVERITY_STYLE, SeverityBadge } from '../components/ui'
import { fmtBytes, fmtInt, fmtPps, fmtRate, fmtTime } from '../lib/format'
import { HEALTH_TONE } from '../lib/palette'
import { setPage, useApp } from '../lib/store'
import type { Severity } from '../lib/types'


export default function Overview() {
  const snap = useApp((s) => s.snapshot)
  const ifaces = useApp((s) => s.interfaces)
  const ifaceName = useApp((s) => s.ifaceName)
  const npcap = useApp((s) => s.appInfo?.npcap)
  if (!snap) return <div className="text-dim text-sm">Loading…</div>

  const a = snap.analytics
  const d = snap.diagnostics
  const issues = d.findings.filter((f) => f.category !== 'capture')
  const worst = issues.reduce<Severity | null>((w, f) => (w === null || SEVERITY_STYLE[f.severity].rank > SEVERITY_STYLE[w].rank ? f.severity : w), null)
  const empty = a.total_packets === 0
  const iface = ifaces.find((i) => i.name === ifaceName)
  const h = d.health

  return (
    <div className="space-y-4">
      <PageHeader
        title="Overview"
        subtitle={snap.source.kind === 'none' ? 'No capture loaded' : snap.source.kind === 'file' ? `Analysing file ${snap.source.name}` : `Live capture on ${snap.source.name}`}
        actions={<button className="btn btn-primary" onClick={() => setPage('capture')}><Radio size={14} />Go to Live Capture</button>}
      />

      <div className="grid gap-3 grid-cols-[repeat(auto-fit,minmax(200px,1fr))]">
        <Metric label="Packets captured" value={fmtInt(a.total_packets)} sub={`${fmtBytes(a.total_bytes)} total`} icon={Package} />
        <Metric label="Throughput" value={fmtRate(a.bytes_per_sec)} sub={`${fmtPps(a.packets_per_sec)} packets/s (3 s avg)`} icon={Activity} />
        <Metric label="Connections" value={fmtInt(a.total_connections)} sub={`${fmtInt(a.active_connections)} active in last 30 s`} icon={Waypoints} />
        <Metric
          label="Detected anomalies"
          value={fmtInt(issues.length)}
          sub={worst ? `Highest severity: ${worst}` : empty ? 'Nothing analysed yet' : 'No findings'}
          icon={TriangleAlert}
          tone={worst ? SEVERITY_STYLE[worst].color : undefined}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(300px,1fr)]">
        <Card>
          <CardTitle icon={Activity}>Real-time traffic · last {a.window_s} s</CardTitle>
          {empty ? (
            <Empty icon={Radio} title="No traffic yet" action={<button className="btn btn-primary" onClick={() => setPage('capture')}>Start a capture</button>}>
              Start a live capture or import a PCAP file. This graph is drawn only from packets NEXUS has actually seen.
            </Empty>
          ) : (
            <TrafficChart series={a.series} kind="bandwidth" height={230} />
          )}
        </Card>

        <Card>
          <CardTitle icon={ShieldCheck}>Network health</CardTitle>
          {h.score === null ? (
            <div className="py-4">
              <div className="text-2xl font-semibold text-dim">{h.label}</div>
              <p className="mt-2 text-xs text-dim leading-5">{h.basis}</p>
            </div>
          ) : (
            <div className="py-1">
              <div className="flex items-baseline gap-3">
                <span className="text-[44px] leading-none font-semibold num" style={{ color: HEALTH_TONE[h.label] }}>{h.score}</span>
                <span className="text-sm font-semibold" style={{ color: HEALTH_TONE[h.label] }}>{h.label}</span>
              </div>
              <p className="mt-3 text-[11px] text-faint leading-4">{h.basis}</p>
            </div>
          )}
          <div className={`mt-3 text-xs rounded-md px-2.5 py-1.5 border ${h.capture_integrity === 'ok' ? 'border-line text-dim' : 'border-warn/40 text-warn bg-warn/[0.07]'}`}>
            Capture integrity: {h.capture_integrity === 'ok' ? 'no local drops reported' : 'local packet drops occurred - treat findings with caution'}
          </div>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardTitle icon={Network}>Protocol distribution</CardTitle>
          {empty ? <p className="text-xs text-faint py-6 text-center">No packets yet.</p> : <ProtocolDonut protocols={a.protocols} total={a.total_packets} />}
        </Card>

        <Card className="lg:col-span-2">
          <CardTitle icon={TriangleAlert} right={<button className="btn !h-6 !px-2 text-[11px]" onClick={() => setPage('rca')}>All findings</button>}>
            Recent diagnostic findings
          </CardTitle>
          {issues.length === 0 ? (
            <p className="text-xs text-dim py-6 text-center">{empty ? 'Findings appear here when NEXUS detects something supported by captured evidence.' : 'No findings so far. Absence of findings does not guarantee the network is healthy: only the captured traffic was analysed.'}</p>
          ) : (
            <ul className="divide-y divide-line-soft">
              {[...issues].sort((x, y) => y.last_ts_us - x.last_ts_us).slice(0, 5).map((f) => (
                <li key={f.id}>
                  <button className="w-full flex items-center gap-3 py-2 text-left cursor-pointer hover:bg-white/[0.03] rounded px-1" onClick={() => setPage('rca')}>
                    <SeverityBadge severity={f.severity} />
                    <span className="flex-1 min-w-0 truncate text-xs">{f.title}{f.flow ? <span className="text-faint"> · {f.flow}</span> : null}</span>
                    <span className="text-faint num text-[11px] shrink-0">{fmtTime(f.last_ts_us)}</span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <Card>
        <CardTitle icon={Radio}>Capture interface</CardTitle>
        <div className="grid gap-x-8 gap-y-2 text-xs sm:grid-cols-2 lg:grid-cols-4">
          <KV k="Interface" v={iface?.friendly_name ?? '-'} />
          <KV k="Status" v={iface ? (iface.status === 'up' ? 'Connected' : iface.status === 'down' ? 'Disconnected' : 'Unknown') : '-'} />
          <KV k="IPv4" v={iface?.ipv4.join(', ') || '-'} mono />
          <KV k="MAC" v={iface?.mac ?? '-'} mono />
          <KV k="Capture driver" v={npcap?.available ? 'Npcap detected' : 'Npcap not found'} />
          <KV k="Buffered packets" v={`${fmtInt(snap.buffered_packets)} in memory`} />
          <KV k="Driver drops" v={fmtInt(snap.capture.kernel_dropped + snap.capture.interface_dropped)} />
          <KV k="Queue drops" v={fmtInt(snap.capture.pipeline_dropped)} />
        </div>
      </Card>
    </div>
  )
}

function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="text-faint text-[11px] uppercase tracking-wide">{k}</div>
      <div className={`truncate mt-0.5 ${mono ? 'kbd-mono' : ''}`} title={v}>{v}</div>
    </div>
  )
}
