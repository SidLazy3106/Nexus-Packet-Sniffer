import { useEffect, useMemo, useState } from 'react'
import { CheckCircle2, ChevronDown, ChevronRight, ClipboardList, Download, Lightbulb, ListChecks, ShieldCheck, Stethoscope, TriangleAlert } from 'lucide-react'
import { Card, CardTitle, ConfidenceBadge, Empty, Metric, PageHeader, SEVERITY_STYLE, SeverityBadge, Tabs } from '../components/ui'
import { fmtInt, fmtMs, fmtTime } from '../lib/format'
import { groupFindings } from '../lib/groupFindings'
import { C, HEALTH_TONE } from '../lib/palette'
import { exportReport, revealPacket, setPage, useApp } from '../lib/store'
import type { Finding, Severity } from '../lib/types'

const SEVERITIES: Severity[] = ['Critical', 'High', 'Medium', 'Low', 'Informational']

export default function RootCause() {
  const snap = useApp((s) => s.snapshot)
  const [tab, setTab] = useState<'findings' | 'timeline' | 'latency'>('findings')
  const [sev, setSev] = useState<Severity | 'All'>('All')
  const [sel, setSel] = useState<string | null>(null)
  const [open, setOpen] = useState<ReadonlySet<string>>(new Set())

  const d = snap?.diagnostics
  const list = useMemo(() => (d?.findings ?? []).filter((f) => sev === 'All' || f.severity === sev), [d?.findings, sev])
  const groups = useMemo(() => groupFindings(list), [list])

  useEffect(() => {
    if (list.length === 0) setSel(null)
    else if (!sel || !list.some((f) => f.id === sel)) setSel(list[0].id)
  }, [list, sel])

  if (!snap || !d) return null
  const h = d.health
  const total = snap.analytics.total_packets
  const finding = list.find((f) => f.id === sel) ?? null
  const capFindings = d.findings.filter((f) => f.category === 'capture')

  return (
    <div className="space-y-4">
      <PageHeader
        title="Root Cause Analysis"
        subtitle="Every finding lists the packets that support it, what could explain it, and what the capture cannot tell you"
        actions={
          <>
            <button className="btn" onClick={() => exportReport('json')} disabled={total === 0}><Download size={14} />Report JSON</button>
            <button className="btn" onClick={() => exportReport('csv')} disabled={total === 0}><Download size={14} />Findings CSV</button>
          </>
        }
      />

      <div className="grid gap-3 grid-cols-[repeat(auto-fit,minmax(200px,1fr))]">
        <Card className="min-w-0">
          <div className="text-[11px] font-semibold uppercase tracking-[0.08em] text-dim">Network health</div>
          {h.score === null ? (
            <div className="mt-1.5 text-lg font-semibold text-dim">{h.label}</div>
          ) : (
            <div className="mt-1.5 flex items-baseline gap-2">
              <span className="text-[30px] leading-8 font-semibold num" style={{ color: HEALTH_TONE[h.label] }}>{h.score}</span>
              <span className="text-sm font-semibold" style={{ color: HEALTH_TONE[h.label] }}>{h.label}</span>
            </div>
          )}
          <div className="mt-1 text-[11px] text-faint leading-4 line-clamp-3" title={h.basis}>{h.basis}</div>
        </Card>
        <Metric label="Capture integrity" value={h.capture_integrity === 'ok' ? 'Intact' : 'Degraded'} sub={h.capture_integrity === 'ok' ? 'Driver and queue reported no drops' : `${capFindings.length} capture finding(s) below`} icon={ShieldCheck} tone={h.capture_integrity === 'ok' ? C.ok : C.warn} />
        <Metric label="Findings" value={d.findings.filter((f) => f.category !== 'capture').length} sub={`${d.findings.filter((f) => f.severity === 'High' || f.severity === 'Critical').length} high / critical`} icon={TriangleAlert} />
        <Metric label="TCP observations" value={fmtInt(d.counters.tcp_retransmissions)} sub={`retransmits · ${fmtInt(d.counters.tcp_duplicate_acks)} dup ACKs · ${fmtInt(d.counters.tcp_out_of_order)} reordered`} icon={ListChecks} />
      </div>

      <div className="flex flex-wrap items-center justify-between gap-3">
        <Tabs value={tab} onChange={setTab} items={[
          { id: 'findings', label: 'Findings', badge: d.findings.length },
          { id: 'timeline', label: 'Timeline', badge: d.timeline.length },
          { id: 'latency', label: 'Latency', badge: d.latency.length },
        ]} />
        {tab === 'findings' && (
          <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by severity">
            {(['All', ...SEVERITIES] as const).map((s) => (
              <button key={s} onClick={() => setSev(s)} aria-pressed={sev === s} className={`h-6 px-2.5 rounded-full text-[11px] font-medium cursor-pointer border transition-colors ${sev === s ? 'bg-accent/15 border-accent/50 text-ink' : 'border-line text-dim hover:text-ink'}`}>{s}</button>
            ))}
          </div>
        )}
      </div>

      {tab === 'findings' && (
        total === 0 ? (
          <Card><Empty icon={Stethoscope} title="Nothing to diagnose yet" action={<button className="btn btn-primary" onClick={() => setPage('capture')}>Open Live Capture</button>}>Capture traffic or import a PCAP. Findings are generated only from observed packets - nothing is simulated.</Empty></Card>
        ) : d.findings.length === 0 ? (
          <Card><Empty icon={CheckCircle2} title="No problems detected in the captured traffic">NEXUS analysed {fmtInt(total)} packets and found no retransmission, reset, DNS, ICMP, malformed-packet or volume patterns above the configured thresholds. This only covers what the capture saw; it does not prove the network is healthy end to end.</Empty></Card>
        ) : (
          <div className="grid gap-4 lg:grid-cols-[minmax(280px,2fr)_minmax(0,3fr)]">
            <Card pad={false} className="overflow-hidden max-h-[70vh] overflow-y-auto">
              {list.length === 0 && <p className="p-4 text-xs text-dim">No findings with severity {sev}.</p>}
              <ul>
                {groups.map((g) => {
                  const single = g.items.length === 1
                  const expanded = single || open.has(g.title) || g.items.some((f) => f.id === sel)
                  const worst = g.items[0]
                  return (
                    <li key={g.title} className="border-b border-line-soft">
                      {!single && (
                        <button
                          onClick={() => setOpen((p) => { const n = new Set(p); if (n.has(g.title)) n.delete(g.title); else n.add(g.title); return n })}
                          aria-expanded={expanded}
                          className="w-full text-left px-4 py-2.5 cursor-pointer transition-colors hover:bg-white/[0.035] flex items-center gap-2"
                        >
                          {expanded ? <ChevronDown size={14} className="text-faint shrink-0" /> : <ChevronRight size={14} className="text-faint shrink-0" />}
                          <SeverityBadge severity={worst.severity} />
                          <span className="text-[13px] font-medium leading-5 min-w-0">{g.title}</span>
                          <span className="ml-auto text-[11px] text-faint num shrink-0">{g.items.length} flows · ×{fmtInt(g.total)}</span>
                        </button>
                      )}
                      {expanded && (
                        <ul>
                          {g.items.map((f) => (
                            <li key={f.id}>
                              <button onClick={() => setSel(f.id)} aria-pressed={sel === f.id} className={`w-full text-left py-2.5 pr-4 cursor-pointer transition-colors hover:bg-white/[0.035] ${single ? "pl-4" : "pl-9"} ${sel === f.id ? "bg-accent/10" : ""}`} style={{ boxShadow: `inset 3px 0 0 ${SEVERITY_STYLE[f.severity].color}` }}>
                                <div className="flex items-center gap-2 flex-wrap">{single && <SeverityBadge severity={f.severity} />}{!single && <span className="text-[11px]" style={{ color: SEVERITY_STYLE[f.severity].color }}>{f.severity}</span>}<span className="text-[11px] text-faint">{f.protocol}</span><span className="text-[11px] text-faint ml-auto num">×{fmtInt(f.count)}</span></div>
                                {single && <div className="mt-1.5 text-[13px] font-medium leading-5">{f.title}</div>}
                                {f.flow && <div className="text-[11px] text-faint kbd-mono truncate mt-0.5">{f.flow}</div>}
                              </button>
                            </li>
                          ))}
                        </ul>
                      )}
                    </li>
                  )
                })}
              </ul>
            </Card>
            {finding ? <FindingDetail f={finding} /> : <Card><Empty title="Select a finding" /></Card>}
          </div>
        )
      )}

      {tab === 'timeline' && (
        <Card>
          <CardTitle icon={ClipboardList}>Chronological evidence</CardTitle>
          {d.timeline.length === 0 ? <p className="text-xs text-dim py-4 text-center">No events yet.</p> : (
            <ol className="relative ml-2 border-l border-line space-y-3 max-h-[64vh] overflow-y-auto pr-2">
              {d.timeline.map((e, i) => (
                <li key={i} className="pl-4 relative">
                  <span className="absolute -left-[5px] top-1.5 size-2 rounded-full" style={{ background: SEVERITY_STYLE[e.severity].color }} />
                  <div className="flex items-center gap-2 flex-wrap text-[11px] text-faint">
                    <span className="num kbd-mono">{fmtTime(e.ts_us)}</span><SeverityBadge severity={e.severity} />
                    {e.packet_no !== null && <button className="text-accent hover:underline cursor-pointer" onClick={() => revealPacket(e.packet_no!)}>packet {e.packet_no}</button>}
                  </div>
                  <div className="text-xs mt-0.5"><span className="font-medium">{e.title}</span> <span className="text-dim">- {e.note}</span></div>
                </li>
              ))}
            </ol>
          )}
        </Card>
      )}

      {tab === 'latency' && (
        <Card pad={false}>
          <div className="p-4 pb-2"><CardTitle icon={ClipboardList}>Latency observations</CardTitle>
            <p className="text-[11px] text-faint leading-4 -mt-1">Each value is the time between two matched packets seen at the capture point (handshake legs, request/response pairs, data and its ACK). None is an end-to-end estimate from a single timestamp.</p></div>
          {d.latency.length === 0 ? <p className="text-xs text-dim p-4 text-center">No matched request/response pairs observed yet.</p> : (
            <div className="overflow-auto max-h-[60vh]">
              <table className="w-full text-xs min-w-[640px]">
                <thead><tr className="text-left text-faint text-[11px] uppercase tracking-wide border-y border-line sticky top-0 bg-raised"><th className="px-4 h-8 font-semibold">Time</th><th className="font-semibold">Type</th><th className="font-semibold">Subject</th><th className="font-semibold text-right px-3">Value</th><th className="font-semibold px-3">Basis</th></tr></thead>
                <tbody>
                  {[...d.latency].reverse().map((l, i) => (
                    <tr key={i} className="border-b border-line-soft/70 hover:bg-white/[0.03]">
                      <td className="px-4 h-8 num kbd-mono text-dim">{fmtTime(l.ts_us)}</td>
                      <td>{l.kind}</td>
                      <td className="kbd-mono truncate max-w-[260px]" title={l.label}>{l.label}</td>
                      <td className="px-3 text-right num font-semibold">{fmtMs(l.value_ms)}</td>
                      <td className="px-3 text-dim"><span className="text-ok">measured</span> · {l.note}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      )}
    </div>
  )
}

function Section({ icon: Icon, title, children, tone }: { icon: typeof Lightbulb; title: string; children: React.ReactNode; tone?: string }) {
  return (
    <div>
      <h4 className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] mb-1.5" style={{ color: tone ?? C.dim }}><Icon size={13} />{title}</h4>
      {children}
    </div>
  )
}

function FindingDetail({ f }: { f: Finding }) {
  return (
    <Card className="space-y-4 min-w-0 max-h-[70vh] overflow-y-auto">
      <div>
        <div className="flex items-center gap-2 flex-wrap"><SeverityBadge severity={f.severity} /><ConfidenceBadge confidence={f.confidence} /><span className="text-[11px] text-faint">{f.protocol} · {f.category}</span></div>
        <h2 className="text-base font-semibold mt-2 leading-6">{f.title}</h2>
        <div className="text-[11px] text-faint num mt-0.5">First {fmtTime(f.first_ts_us)} · last {fmtTime(f.last_ts_us)} · {fmtInt(f.count)} occurrence{f.count === 1 ? '' : 's'}{f.flow ? ` · ${f.flow}` : ''}</div>
      </div>

      <Section icon={CheckCircle2} title="Observed (confirmed from packets)" tone={C.ok}>
        <p className="text-xs leading-5">{f.description}</p>
        {f.measurements.length > 0 && (
          <dl className="mt-2 grid grid-cols-[auto_1fr_auto] gap-x-4 gap-y-1 text-xs">
            {f.measurements.map((m, i) => (
              <div key={i} className="contents"><dt className="text-dim">{m.label}</dt><dd className="num font-semibold kbd-mono">{m.value}</dd><dd className="text-[10px] uppercase tracking-wide self-center" style={{ color: m.kind === 'measured' ? C.ok : C.warn }}>{m.kind}</dd></div>
            ))}
          </dl>
        )}
      </Section>

      <Section icon={ClipboardList} title={`Evidence (${f.evidence.length}${f.count > f.evidence.length ? ` of ${fmtInt(f.count)}` : ''})`}>
        <ul className="space-y-1.5">
          {f.evidence.map((e, i) => (
            <li key={i} className="flex gap-2.5 text-xs items-baseline">
              <span className="num kbd-mono text-faint shrink-0">{fmtTime(e.ts_us)}</span>
              {e.packet_no !== null ? <button className="text-accent hover:underline cursor-pointer num shrink-0" onClick={() => revealPacket(e.packet_no!)} title="Show in Packet Explorer">#{e.packet_no}</button> : <span className="text-faint shrink-0">aggregate</span>}
              <span className="text-ink/90 min-w-0 break-words">{e.note}</span>
            </li>
          ))}
        </ul>
      </Section>

      <Section icon={Lightbulb} title="Possible causes (hypotheses, not confirmed)" tone={C.warn}>
        <ul className="list-disc pl-4 space-y-1 text-xs leading-5 marker:text-faint">{f.possible_causes.map((c, i) => <li key={i}>{c}</li>)}</ul>
      </Section>

      <Section icon={ListChecks} title="Recommended troubleshooting" tone={C.celadon}>
        <ol className="list-decimal pl-4 space-y-1 text-xs leading-5 marker:text-faint">{f.recommendations.map((c, i) => <li key={i}>{c}</li>)}</ol>
      </Section>

      <Section icon={TriangleAlert} title="Limits of this conclusion">
        <ul className="list-disc pl-4 space-y-1 text-xs leading-5 text-dim marker:text-faint">{f.limitations.map((c, i) => <li key={i}>{c}</li>)}</ul>
      </Section>
    </Card>
  )
}
