import { useCallback, useEffect, useState } from 'react'
import { Check, Download, FileDown, FileUp, FolderOpen, History, Pencil, Trash2, X } from 'lucide-react'
import { Card, Empty, PageHeader } from '../components/ui'
import { api, errorText } from '../lib/api'
import { exportCapture, exportReport, importFile, notify, openSession, useApp, usePackets } from '../lib/store'
import { fmtBytes, fmtDateTime, fmtDuration, fmtInt } from '../lib/format'
import type { SessionRecord } from '../lib/types'

export default function Sessions() {
  const [list, setList] = useState<SessionRecord[] | null>(null)
  const [err, setErr] = useState<string | null>(null)
  const [confirmId, setConfirmId] = useState<number | null>(null)
  const [renaming, setRenaming] = useState<{ id: number; name: string } | null>(null)
  const busy = useApp((s) => s.busy)
  const snap = useApp((s) => s.snapshot)
  const total = snap?.total_packets ?? 0
  const capturing = snap?.capture.status === 'capturing' || snap?.capture.status === 'paused'
  const { rows } = usePackets()

  const refresh = useCallback(() => {
    api.listSessions().then((l) => { setList(l); setErr(null) }, (e) => setErr(errorText(e)))
  }, [])

  // Reload when a capture stops, an import finishes, or the loaded capture changes.
  useEffect(refresh, [refresh, total === 0, capturing, snap?.importing])

  const remove = async (id: number) => {
    try { await api.deleteSession(id); setConfirmId(null); refresh() } catch (e) { notify('error', errorText(e)) }
  }
  const rename = async () => {
    if (!renaming) return
    try { await api.renameSession(renaming.id, renaming.name); setRenaming(null); refresh() } catch (e) { notify('error', errorText(e)) }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Capture Sessions"
        subtitle="Live captures are recorded automatically; imported files are listed here too"
        actions={
          <>
            <button className="btn" onClick={() => importFile()} disabled={busy || capturing}><FileUp size={14} />Import PCAP / PCAPNG</button>
            <button className="btn" onClick={() => exportCapture(null)} disabled={busy || rows.length === 0}><Download size={14} />Export loaded capture</button>
            <button className="btn" onClick={() => exportReport('json')} disabled={total === 0}><FileDown size={14} />Report JSON</button>
            <button className="btn" onClick={() => exportReport('csv')} disabled={total === 0}><FileDown size={14} />Report CSV</button>
          </>
        }
      />
      {err && <div className="text-xs text-crit" role="alert">{err}</div>}

      <Card pad={false}>
        {list === null ? (
          <p className="p-6 text-xs text-dim">Loading sessions…</p>
        ) : list.length === 0 ? (
          <Empty icon={History} title="No saved sessions yet">Stop a live capture or import a file and it will appear here with its diagnostic summary.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs min-w-[860px]">
              <thead>
                <tr className="text-left text-faint text-[11px] uppercase tracking-wide border-b border-line">
                  <th className="px-4 h-9 font-semibold">Session</th><th className="font-semibold">Started</th><th className="font-semibold">Duration</th>
                  <th className="font-semibold text-right">Packets</th><th className="font-semibold text-right px-3" title="Bytes observed on the wire during the capture">Traffic</th><th className="font-semibold">Health</th><th className="font-semibold text-right px-4">Actions</th>
                </tr>
              </thead>
              <tbody>
                {list.map((s) => (
                  <tr key={s.id} className="border-b border-line-soft/70 hover:bg-white/[0.03]">
                    <td className="px-4 py-2 max-w-[280px]">
                      {renaming?.id === s.id ? (
                        <div className="flex items-center gap-1">
                          <input className="input !h-7 flex-1" autoFocus value={renaming.name} onChange={(e) => setRenaming({ id: s.id, name: e.target.value })} onKeyDown={(e) => { if (e.key === 'Enter') rename(); if (e.key === 'Escape') setRenaming(null) }} aria-label="Session name" />
                          <button className="btn !px-1.5 !h-7" onClick={rename} aria-label="Save name"><Check size={13} /></button>
                          <button className="btn !px-1.5 !h-7" onClick={() => setRenaming(null)} aria-label="Cancel"><X size={13} /></button>
                        </div>
                      ) : (
                        <>
                          <div className="font-medium truncate" title={s.name}>{s.name}</div>
                          <div className="text-[11px] text-faint truncate">{s.source === 'live' ? 'Live' : 'Imported'}{s.filter ? ` · filter: ${s.filter}` : ''}{!s.file_exists && s.file_path ? ' · file missing' : ''}{!s.file_path ? ' · no capture file' : ''}</div>
                        </>
                      )}
                    </td>
                    <td className="text-dim whitespace-nowrap">{fmtDateTime(s.started_ms)}</td>
                    <td className="text-dim num whitespace-nowrap">{fmtDuration(s.ended_ms - s.started_ms)}</td>
                    <td className="text-right num">{fmtInt(s.packet_count)}</td>
                    <td className="text-right num px-3 text-dim">{fmtBytes(s.byte_count)}</td>
                    <td className="whitespace-nowrap">{s.health_score !== null ? <span className="num">{s.health_score} <span className="text-dim">{s.health_label}</span></span> : <span className="text-faint">{s.health_label || '-'}</span>}<span className="text-faint ml-2">{s.finding_count} finding{s.finding_count === 1 ? '' : 's'}</span></td>
                    <td className="px-4">
                      <div className="flex justify-end gap-1.5">
                        {confirmId === s.id ? (
                          <>
                            <span className="self-center text-[11px] text-dim mr-1">{s.source === 'live' ? 'Delete session and its capture file?' : 'Remove from list?'}</span>
                            <button className="btn btn-danger !h-7" onClick={() => remove(s.id)}>Delete</button>
                            <button className="btn !h-7" onClick={() => setConfirmId(null)}>Cancel</button>
                          </>
                        ) : (
                          <>
                            <button className="btn !h-7" onClick={() => openSession(s.id)} disabled={busy || capturing || !s.file_exists} title={s.file_exists ? 'Reopen for analysis' : 'The capture file is no longer available'}><FolderOpen size={13} />Open</button>
                            <button className="btn !h-7 !px-2" onClick={() => exportReport('json', s.id)} title="Export saved report (JSON)" aria-label="Export report JSON"><FileDown size={13} /></button>
                            <button className="btn !h-7 !px-2" onClick={() => setRenaming({ id: s.id, name: s.name })} title="Rename" aria-label="Rename session"><Pencil size={13} /></button>
                            <button className="btn !h-7 !px-2" onClick={() => setConfirmId(s.id)} title="Delete" aria-label="Delete session"><Trash2 size={13} /></button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
      <p className="text-[11px] text-faint leading-4">Recorded captures are stored in your NEXUS data folder and may contain sensitive information. Deleting a live session also deletes its capture file; imported files are never deleted from their original location.</p>
    </div>
  )
}
