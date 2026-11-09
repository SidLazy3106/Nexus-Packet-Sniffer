import { useEffect, useState } from 'react'
import type { ReactNode } from 'react'
import { RotateCcw, Save } from 'lucide-react'
import { Card, CardTitle, PageHeader } from '../components/ui'
import { saveSettings, useApp } from '../lib/store'
import type { DiagConfig, Settings } from '../lib/types'

type DiagKey = keyof DiagConfig
const THRESHOLDS: { key: DiagKey; label: string; help: string; step?: number }[] = [
  { key: 'dupack_threshold', label: 'Duplicate ACK threshold', help: 'Consecutive identical ACKs before a finding (RFC 5681 uses 3).' },
  { key: 'retrans_ratio_medium', label: 'Retransmission ratio - Medium', help: 'Fraction of segments retransmitted (needs ≥ 20 segments).', step: 0.005 },
  { key: 'retrans_ratio_high', label: 'Retransmission ratio - High', help: 'Fraction of segments retransmitted for High severity.', step: 0.005 },
  { key: 'reorder_window_ms', label: 'Reordering window (ms)', help: 'A late lower sequence number within this time is reordering, otherwise a retransmission.' },
  { key: 'handshake_slow_ms', label: 'Slow handshake (ms)', help: 'TCP handshake duration reported as slow.' },
  { key: 'syn_timeout_s', label: 'SYN timeout (s)', help: 'Wait before a SYN with no reply counts as a failed attempt.', step: 0.5 },
  { key: 'conn_fail_min', label: 'Failed attempts to report', help: 'Failed connections to one host:port before a finding.' },
  { key: 'dns_slow_ms', label: 'Slow DNS (ms)', help: 'Measured query-to-response time reported as slow.' },
  { key: 'dns_timeout_s', label: 'DNS timeout (s)', help: 'Wait before a query counts as unanswered.', step: 0.5 },
  { key: 'dns_unanswered_min', label: 'Unanswered DNS to report', help: 'Unanswered queries to one server before a finding.' },
  { key: 'rtt_variation_factor', label: 'RTT variation factor', help: 'Sample must exceed this multiple of the flow median.', step: 0.5 },
  { key: 'rtt_min_ms', label: 'RTT variation minimum (ms)', help: 'Ignore variations smaller than this.' },
  { key: 'rtt_min_samples', label: 'RTT samples required', help: 'Samples per flow before variation is judged.' },
  { key: 'spike_sigma', label: 'Traffic spike (σ)', help: 'Standard deviations above the 60 s baseline.', step: 0.5 },
  { key: 'spike_min_bytes', label: 'Spike minimum (bytes/s)', help: 'Ignore spikes below this volume.' },
  { key: 'mix_share', label: 'Protocol dominance share', help: 'ICMP/ARP/DNS share of packets considered unusual (0-1).', step: 0.05 },
  { key: 'malformed_min', label: 'Malformed packets to report', help: 'Observations of one kind before a finding.' },
  { key: 'ratio_min_segments', label: 'Segments for ratio severity', help: 'A flow needs this many segments before its retransmission ratio can raise severity.' },
  { key: 'dupack_medium_run', label: 'Duplicate ACK run - Medium', help: 'A run of this many identical ACKs raises the finding to Medium.' },
  { key: 'rst_burst_min', label: 'Resets from one host', help: 'RST segments from one address before a "many resets" finding.' },
  { key: 'conn_fail_high', label: 'Failed attempts - High', help: 'Failed connections to one host:port that make the finding High.' },
  { key: 'rtt_medium_ms', label: 'RTT outlier - Medium (ms)', help: 'An outlier above this is Medium instead of Low.' },
  { key: 'gap_low_count', label: 'Sequence gaps - Low', help: 'Gaps in a capture before the gap finding is Low instead of Informational.' },
  { key: 'malformed_medium_count', label: 'Malformed - Medium', help: 'Observations of one kind before the finding is Medium instead of Low.' },
  { key: 'spike_high_sigma', label: 'Spike - Low severity (σ)', help: 'A spike beyond this many sigma (and the ratio below) is Low instead of Informational.', step: 0.5 },
  { key: 'spike_high_ratio', label: 'Spike - ratio to baseline', help: 'Multiple of the baseline mean required for the higher severity.', step: 0.5 },
  { key: 'health_min_packets', label: 'Packets for health score', help: 'Below this the score reads "Insufficient data".' },
]

function Field({ label, help, children }: { label: string; help?: string; children: ReactNode }) {
  return (
    <label className="grid gap-1.5 text-xs min-w-0">
      <span className="font-medium">{label}</span>
      {children}
      {help && <span className="text-[11px] text-faint leading-4">{help}</span>}
    </label>
  )
}

function Toggle({ checked, onChange, label, help }: { checked: boolean; onChange: (v: boolean) => void; label: string; help?: string }) {
  return (
    <label className="flex items-start gap-3 text-xs cursor-pointer">
      <input type="checkbox" className="mt-0.5 size-4 accent-accent" checked={checked} onChange={(e) => onChange(e.target.checked)} />
      <span><span className="font-medium block">{label}</span>{help && <span className="text-[11px] text-faint leading-4 block mt-0.5">{help}</span>}</span>
    </label>
  )
}

export default function SettingsPage() {
  const stored = useApp((s) => s.settings)
  const ifaces = useApp((s) => s.interfaces)
  const info = useApp((s) => s.appInfo)
  const busy = useApp((s) => s.busy)
  const [s, setS] = useState<Settings | null>(stored)
  useEffect(() => setS(stored), [stored])
  if (!s || !stored) return <p className="text-sm text-dim">Loading settings…</p>

  const dirty = JSON.stringify(s) !== JSON.stringify(stored)
  const up = <K extends keyof Settings>(k: K, v: Settings[K]) => setS({ ...s, [k]: v })
  const num = (v: string, fallback: number) => (v === '' || Number.isNaN(Number(v)) ? fallback : Number(v))
  const upDiag = (k: DiagKey, v: number) => setS({ ...s, diag: { ...s.diag, [k]: v } })

  return (
    <div className="space-y-4 max-w-[1100px]">
      <PageHeader
        title="Settings"
        subtitle="Capture parameters apply to the next capture; display options apply immediately"
        actions={
          <>
            <button className="btn" onClick={() => setS(stored)} disabled={!dirty}><RotateCcw size={14} />Revert</button>
            <button className="btn btn-primary" onClick={() => saveSettings(s)} disabled={!dirty || busy}><Save size={14} />Save changes</button>
          </>
        }
      />

      <div className="grid gap-4 lg:grid-cols-2">
        <Card className="space-y-4">
          <CardTitle>Appearance and defaults</CardTitle>
          <Field label="Theme">
            <select className="input" value={s.theme} onChange={(e) => up('theme', e.target.value)}>
              <option value="dark">Dark - sumi ink (default)</option>
              <option value="graphite">Dark - graphite</option>
            </select>
          </Field>
          <Field label="Default network interface">
            <select className="input" value={s.default_interface ?? ''} onChange={(e) => up('default_interface', e.target.value || null)}>
              <option value="">Automatic (first connected)</option>
              {ifaces.map((i) => <option key={i.name} value={i.name}>{i.friendly_name}</option>)}
            </select>
          </Field>
          <Field label="Default capture filter (BPF)" help="Applied when NEXUS starts. Example: not port 443">
            <input className="input kbd-mono" value={s.default_filter} onChange={(e) => up('default_filter', e.target.value)} spellCheck={false} />
          </Field>
          <Field label="Default analytics window (seconds)">
            <input className="input num" type="number" min={10} max={3600} value={s.analytics_window_s} onChange={(e) => up('analytics_window_s', num(e.target.value, 60))} />
          </Field>
        </Card>

        <Card className="space-y-4">
          <CardTitle>Capture buffers and retention</CardTitle>
          <Field label="Packets kept in memory" help="Oldest packets are evicted beyond this limit (1,000 - 5,000,000). Analytics keep counting.">
            <input className="input num" type="number" min={1000} max={5000000} step={10000} value={s.max_packets_in_memory} onChange={(e) => up('max_packets_in_memory', num(e.target.value, 200000))} />
          </Field>
          <Field label="Processing queue capacity (packets)" help="Bounded queue between capture and analysis. When full, packets are dropped and counted as queue drops.">
            <input className="input num" type="number" min={256} max={262144} step={256} value={s.queue_capacity} onChange={(e) => up('queue_capacity', num(e.target.value, 8192))} />
          </Field>
          <Field label="Payload bytes retained per packet" help="Bytes kept after the headers, in memory and in recorded/exported files. 0 keeps headers only. Analysis always sees the full packet before this cut.">
            <input className="input num" type="number" min={0} max={65535} value={s.payload_retention_bytes} onChange={(e) => up('payload_retention_bytes', num(e.target.value, 256))} />
          </Field>
          <Field label="Recorded session size limit (MB)" help="Recording to disk stops at this size; capture and analysis continue.">
            <input className="input num" type="number" min={1} max={20480} value={s.max_session_file_mb} onChange={(e) => up('max_session_file_mb', num(e.target.value, 512))} />
          </Field>
        </Card>

        <Card className="space-y-4">
          <CardTitle>Privacy and export</CardTitle>
          <Toggle checked={s.redact_payload_display} onChange={(v) => up('redact_payload_display', v)} label="Mask payload bytes in the hex viewer" help="Only headers are shown; payload bytes appear as ··. Applies immediately." />
          <Toggle checked={s.record_sessions} onChange={(v) => up('record_sessions', v)} label="Record live captures as sessions" help="Writes retained packets to a PCAP/PCAPNG file in the NEXUS data folder so the session can be reopened. Turn off to keep captures in memory only." />
          <Field label="Default export format">
            <select className="input" value={s.default_export_format} onChange={(e) => up('default_export_format', e.target.value as Settings['default_export_format'])}>
              <option value="pcapng">PCAPNG</option>
              <option value="pcap">PCAP</option>
            </select>
          </Field>
          <div className="rounded-md border border-line bg-surface/60 p-3 text-[11px] leading-5 text-dim space-y-1">
            <p>{info?.privacy_notice}</p>
            <p>Data folder: <span className="kbd-mono text-ink break-all">{info?.data_dir}</span></p>
          </div>
        </Card>

        <Card className="space-y-3">
          <CardTitle>Capture driver</CardTitle>
          <div className="text-xs space-y-2">
            <div className={info?.npcap.available ? 'text-ok' : 'text-warn'}>{info?.npcap.available ? 'Npcap detected' : 'Npcap not detected'}</div>
            <p className="text-dim leading-5">{info?.npcap.detail}</p>
            <p className="text-dim leading-5">{info?.npcap.admin_note}</p>
            <p className="text-[11px] text-faint">Npcap is a separate product with its own licence and is never bundled or installed by NEXUS.</p>
          </div>
        </Card>
      </div>

      <Card>
        <CardTitle>Diagnostic thresholds</CardTitle>
        <p className="text-[11px] text-faint leading-4 mb-4">These control when observations become findings. Changing them changes what is reported, not what is captured.</p>
        <div className="grid gap-x-6 gap-y-4 sm:grid-cols-2 lg:grid-cols-3">
          {THRESHOLDS.map((t) => (
            <Field key={t.key} label={t.label} help={t.help}>
              <input className="input num" type="number" step={t.step ?? 1} min={0} value={s.diag[t.key]} onChange={(e) => upDiag(t.key, num(e.target.value, s.diag[t.key]))} />
            </Field>
          ))}
        </div>
      </Card>
    </div>
  )
}
