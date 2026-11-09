import { Layers, ShieldAlert } from 'lucide-react'
import { Bar, Card, CardTitle, Empty, PageHeader, ProtoChip, protoColor, StatRow } from '../components/ui'
import { fmtBytes, fmtInt, pct } from '../lib/format'
import { C } from '../lib/palette'
import { setPage, useApp } from '../lib/store'

const SUPPORTED = [
  ['Ethernet II', 'with 802.1Q VLAN tags (up to two)'],
  ['IPv4', 'options, fragmentation flags and offsets'],
  ['IPv6', 'hop-by-hop, routing, destination-options and fragment extension headers'],
  ['TCP', 'flags, sequence/ack, window, options (MSS, window scale, SACK, timestamps)'],
  ['UDP', 'length validation'],
  ['ICMP / ICMPv6', 'echo, unreachable, time exceeded, neighbour discovery'],
  ['ARP', 'requests, replies, gratuitous ARP'],
  ['DNS', 'header, first question, response code (UDP only)'],
  ['DHCP', 'message type, transaction ID, client MAC'],
]

export default function Protocols() {
  const snap = useApp((s) => s.snapshot)
  if (!snap) return null
  const a = snap.analytics
  const c = snap.diagnostics.counters
  const anomalies = snap.diagnostics.findings.filter((f) => f.category === 'protocol')
  const maxBytes = Math.max(...a.protocols.map((p) => p.bytes), 1)

  return (
    <div className="space-y-4">
      <PageHeader title="Protocol Analysis" subtitle="Protocol mix and header-level observations from captured packets" />

      <Card pad={false}>
        <div className="p-4 pb-2"><CardTitle icon={Layers}>Protocol hierarchy</CardTitle></div>
        {a.protocols.length === 0 ? (
          <Empty icon={Layers} title="No protocol data yet" action={<button className="btn btn-primary" onClick={() => setPage('capture')}>Open Live Capture</button>}>
            Protocol statistics are computed from the packets NEXUS decodes.
          </Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs min-w-[640px]">
              <thead>
                <tr className="text-left text-faint text-[11px] uppercase tracking-wide border-y border-line">
                  <th className="font-semibold px-4 h-8">Protocol</th>
                  <th className="font-semibold px-3 text-right">Packets</th>
                  <th className="font-semibold px-3 text-right">% packets</th>
                  <th className="font-semibold px-3 text-right">Bytes</th>
                  <th className="font-semibold px-4 w-[28%]">Share of bytes</th>
                </tr>
              </thead>
              <tbody>
                {a.protocols.map((p) => (
                  <tr key={p.name} className="border-b border-line-soft/70 hover:bg-white/[0.03]">
                    <td className="px-4 h-9"><ProtoChip protocol={p.name} /></td>
                    <td className="px-3 text-right num">{fmtInt(p.packets)}</td>
                    <td className="px-3 text-right num text-dim">{pct(p.packets, a.total_packets)}</td>
                    <td className="px-3 text-right num">{fmtBytes(p.bytes)}</td>
                    <td className="px-4"><Bar value={(p.bytes / maxBytes) * 100} color={protoColor(p.name)} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardTitle>Transport and protocol counters</CardTitle>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2.5 text-xs">
            <StatRow label="TCP packets" value={a.tcp_packets} />
            <StatRow label="UDP packets" value={a.udp_packets} />
            <StatRow label="ICMP / ICMPv6 packets" value={a.icmp_packets} />
            <StatRow label="Other packets" value={a.other_packets} />
            <StatRow label="TCP handshakes completed" value={c.tcp_handshakes} />
            <StatRow label="TCP resets" value={c.tcp_resets} />
            <StatRow label="DNS queries / responses" value={`${fmtInt(c.dns_queries)} / ${fmtInt(c.dns_responses)}`} />
            <StatRow label="ICMP error messages" value={c.icmp_errors} />
            <StatRow label="IP fragments" value={c.fragments} />
            <StatRow label="Malformed header observations" value={fmtInt(c.malformed)} tone={c.malformed > 0 ? C.crit : undefined} />
          </dl>
        </Card>

        <Card>
          <CardTitle icon={ShieldAlert}>Protocol anomalies</CardTitle>
          {anomalies.length === 0 ? (
            <p className="text-xs text-dim leading-5 py-2">No malformed or inconsistent headers were observed in the packets analysed so far.</p>
          ) : (
            <ul className="space-y-2.5">
              {anomalies.map((f) => (
                <li key={f.id} className="text-xs">
                  <div className="font-semibold">{f.title} <span className="text-faint font-normal num">×{f.count}</span></div>
                  <div className="text-dim mt-0.5 leading-5">{f.description}</div>
                </li>
              ))}
            </ul>
          )}
          <button className="btn mt-3" onClick={() => setPage('rca')}>Open Root Cause Analysis</button>
        </Card>
      </div>

      <Card>
        <CardTitle>Decoder coverage</CardTitle>
        <ul className="grid gap-x-8 gap-y-1.5 text-xs sm:grid-cols-2">
          {SUPPORTED.map(([n, d]) => (
            <li key={n} className="flex gap-2"><span className="font-semibold w-[104px] shrink-0">{n}</span><span className="text-dim">{d}</span></li>
          ))}
        </ul>
        <p className="mt-3 text-[11px] text-faint leading-4">Checksums are intentionally not validated: NIC checksum offload makes them unreliable in local captures. Fragments are flagged but not reassembled. Encrypted payloads are never decrypted.</p>
      </Card>
    </div>
  )
}

