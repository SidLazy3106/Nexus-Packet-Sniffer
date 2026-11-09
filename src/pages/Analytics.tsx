import { Activity, BarChart3, Clock, Network, Repeat2, Users } from 'lucide-react'
import { ProtocolDonut, TopList, TrafficChart } from '../components/Charts'
import { Card, CardTitle, Empty, Metric, PageHeader, StatRow, Tabs } from '../components/ui'
import { api } from '../lib/api'
import { fmtBytes, fmtInt, fmtMs, fmtPps, fmtRate, fmtTime } from '../lib/format'
import { notify, setPage, useApp } from '../lib/store'

const WINDOWS = [
  { id: '30', label: '30 s' },
  { id: '60', label: '1 min' },
  { id: '300', label: '5 min' },
  { id: '900', label: '15 min' },
  { id: '3600', label: '1 hour' },
] as const

export default function Analytics() {
  const snap = useApp((s) => s.snapshot)
  if (!snap) return null
  const a = snap.analytics
  const d = snap.diagnostics
  const c = d.counters
  const empty = a.total_packets === 0

  const setWindow = (id: string) => {
    api.setAnalyticsWindow(Number(id)).catch((e) => notify('error', String(e)))
  }

  const lat = d.latency
  const byKind = new Map<string, number[]>()
  for (const l of lat) byKind.set(l.kind, [...(byKind.get(l.kind) ?? []), l.value_ms])
  const summary = [...byKind.entries()].map(([kind, v]) => {
    const s = [...v].sort((x, y) => x - y)
    return { kind, n: s.length, min: s[0], median: s[Math.floor(s.length / 2)], max: s[s.length - 1] }
  })

  return (
    <div className="space-y-4">
      <PageHeader
        title="Traffic Analytics"
        subtitle="All figures are aggregated from captured packets"
        actions={<Tabs value={String(a.window_s)} onChange={setWindow} items={WINDOWS.map((w) => ({ id: w.id, label: w.label }))} />}
      />

      {empty ? (
        <Card><Empty icon={BarChart3} title="No traffic to analyse" action={<button className="btn btn-primary" onClick={() => setPage('capture')}>Open Live Capture</button>}>Graphs and rankings appear as soon as packets are captured or a file is imported.</Empty></Card>
      ) : (
        <>
          <div className="grid gap-3 grid-cols-[repeat(auto-fit,minmax(190px,1fr))]">
            <Metric label="Packets / second" value={fmtPps(a.packets_per_sec)} sub="3 s average" icon={Activity} />
            <Metric label="Bandwidth" value={fmtRate(a.bytes_per_sec)} sub={`${fmtBytes(a.bytes_per_sec)}/s`} icon={Network} />
            <Metric label="Total captured" value={fmtBytes(a.total_bytes)} sub={`${fmtInt(a.total_packets)} packets`} icon={BarChart3} />
            <Metric label="Connections" value={fmtInt(a.total_connections)} sub={`${fmtInt(a.active_connections)} active`} icon={Repeat2} />
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card><CardTitle icon={Activity}>Packets per second</CardTitle><TrafficChart series={a.series} kind="packets" /></Card>
            <Card><CardTitle icon={Network}>Bandwidth utilisation</CardTitle><TrafficChart series={a.series} kind="bandwidth" /></Card>
          </div>

          <div className="grid gap-4 lg:grid-cols-3">
            <Card><CardTitle icon={BarChart3}>Protocol distribution</CardTitle><ProtocolDonut protocols={a.protocols} total={a.total_packets} />
              <div className="mt-3 grid grid-cols-4 gap-2 text-center text-[11px]">
                {[['TCP', a.tcp_packets], ['UDP', a.udp_packets], ['ICMP', a.icmp_packets], ['Other', a.other_packets]].map(([k, v]) => (
                  <div key={k as string} className="rounded-md bg-surface border border-line-soft py-1.5"><div className="text-faint">{k}</div><div className="num font-semibold text-xs">{fmtInt(v as number)}</div></div>
                ))}
              </div>
            </Card>
            <Card><CardTitle icon={Users}>Top sources</CardTitle><TopList items={a.top_sources} empty="No sources yet." /></Card>
            <Card><CardTitle icon={Users}>Top destinations</CardTitle><TopList items={a.top_destinations} empty="No destinations yet." /></Card>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <Card>
              <CardTitle icon={Repeat2}>TCP and connection statistics</CardTitle>
              <dl className="grid grid-cols-2 gap-x-6 gap-y-2.5 text-xs">
                <StatRow label="Handshakes completed" value={fmtInt(c.tcp_handshakes)} />
                <StatRow label="Connections refused (RST)" value={fmtInt(c.tcp_refused)} />
                <StatRow label="TCP resets" value={fmtInt(c.tcp_resets)} />
                <StatRow label="Retransmissions" value={fmtInt(c.tcp_retransmissions)} />
                <StatRow label="Duplicate ACKs" value={fmtInt(c.tcp_duplicate_acks)} />
                <StatRow label="Out-of-order segments" value={fmtInt(c.tcp_out_of_order)} />
                <StatRow label="Sequence gaps" value={fmtInt(c.tcp_sequence_gaps)} />
                <StatRow label="Untracked packets" value={fmtInt(a.untracked_packets)} />
              </dl>
              <p className="mt-3 text-[11px] text-faint leading-4">Retransmissions, duplicate ACKs and reordering are inferences from TCP sequence numbers at the capture point. They are not packet-loss measurements, and local capture drops are shown separately below.</p>
              <div className="mt-2 text-[11px] text-dim num">Local capture drops: driver {fmtInt(snap.capture.kernel_dropped + snap.capture.interface_dropped)} · queue {fmtInt(snap.capture.pipeline_dropped)}</div>
            </Card>

            <Card>
              <CardTitle icon={Clock}>Latency observations (measured)</CardTitle>
              {summary.length === 0 ? <p className="text-xs text-dim py-4 text-center">No matched packet pairs yet (needs TCP handshakes, ICMP echo or DNS exchanges).</p> : (
                <table className="w-full text-xs">
                  <thead><tr className="text-left text-faint text-[11px] uppercase tracking-wide border-b border-line"><th className="font-semibold h-7">Type</th><th className="font-semibold text-right">n</th><th className="font-semibold text-right">Min</th><th className="font-semibold text-right">Median</th><th className="font-semibold text-right">Max</th></tr></thead>
                  <tbody>{summary.map((s) => (
                    <tr key={s.kind} className="border-b border-line-soft/70"><td className="h-8">{s.kind}</td><td className="text-right num">{s.n}</td><td className="text-right num">{fmtMs(s.min)}</td><td className="text-right num">{fmtMs(s.median)}</td><td className="text-right num">{fmtMs(s.max)}</td></tr>
                  ))}</tbody>
                </table>
              )}
              {lat.length > 0 && <p className="mt-3 text-[11px] text-faint leading-4">Latest: {lat[lat.length - 1].kind} {fmtMs(lat[lat.length - 1].value_ms)} at {fmtTime(lat[lat.length - 1].ts_us)}. Values are intervals between matched packets at the capture point.</p>}
            </Card>
          </div>
        </>
      )}
    </div>
  )
}

