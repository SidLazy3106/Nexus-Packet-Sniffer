import { useMemo, useState } from 'react'
import { ChevronLeft, ChevronRight, Search } from 'lucide-react'
import { PacketInspector } from '../components/PacketInspector'
import { PacketTable } from '../components/PacketTable'
import { Empty, PageHeader } from '../components/ui'
import { parseTerms } from '../lib/filter'
import { fmtInt } from '../lib/format'
import { selectPacket, setPage, useApp, usePackets } from '../lib/store'
import type { Sort } from '../lib/useRows'
import { useViewRows } from '../lib/useRows'

const EMPTY: ReadonlySet<number> = new Set()
const NO_PROTOCOLS: ReadonlySet<string> = new Set()
const NOOP_SORT: Sort = { key: 'no', dir: 1 }

export default function Explorer() {
  const { rows, version } = usePackets()
  const selectedNo = useApp((s) => s.selectedNo)
  const focusNo = useApp((s) => s.focusNo)
  const [text, setText] = useState('')
  const terms = useMemo(() => parseTerms(text), [text])
  const view = useViewRows(rows, version, terms, NO_PROTOCOLS, NOOP_SORT)

  const idx = selectedNo === null ? -1 : view.findIndex((r) => r.no === selectedNo)
  const step = (d: number) => {
    const next = view[Math.max(0, Math.min(view.length - 1, (idx < 0 ? 0 : idx) + d))]
    if (next) selectPacket(next.no)
  }

  if (rows.length === 0) {
    return (
      <>
        <PageHeader title="Packet Explorer" subtitle="Decoded protocol hierarchy, field explanations and raw bytes" />
        <div className="card">
          <Empty icon={Search} title="No packets to inspect" action={<button className="btn btn-primary" onClick={() => setPage('capture')}>Open Live Capture</button>}>
            Capture traffic or import a PCAP/PCAPNG file, then select a packet to see every decoded header field.
          </Empty>
        </div>
      </>
    )
  }

  return (
    <div className="flex flex-col h-full min-h-0 gap-3">
      <PageHeader
        title="Packet Explorer"
        subtitle="Click any field to highlight its bytes and read what it means"
        actions={
          <>
            <button className="btn !px-2" onClick={() => step(-1)} disabled={idx <= 0} aria-label="Previous packet"><ChevronLeft size={15} /></button>
            <button className="btn !px-2" onClick={() => step(1)} disabled={idx < 0 || idx >= view.length - 1} aria-label="Next packet"><ChevronRight size={15} /></button>
          </>
        }
      />
      <div className="grid gap-3 flex-1 min-h-0 grid-cols-[minmax(300px,380px)_minmax(0,1fr)] max-[1000px]:grid-cols-1 max-[1000px]:grid-rows-[240px_minmax(0,1fr)]">
        <div className="flex flex-col min-h-0 gap-2">
          <div className="relative">
            <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-faint" />
            <input className="input w-full !pl-8 kbd-mono" placeholder="Filter packets…" value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} aria-label="Filter packets" />
          </div>
          <div className="flex-1 min-h-0">
            <PacketTable rows={view} selectedNo={selectedNo} checked={EMPTY} onSelect={(no) => selectPacket(no)} autoScroll={false} sort={NOOP_SORT} onSort={() => {}} compact focusNo={focusNo} emptyHint="No packets match." />
          </div>
          <div className="text-[11px] text-faint num px-1">{fmtInt(view.length)} packets</div>
        </div>
        <div className="card overflow-auto min-h-0">
          <PacketInspector no={selectedNo} />
        </div>
      </div>
    </div>
  )
}
