import { invoke } from '@tauri-apps/api/core'
import { open, save } from '@tauri-apps/plugin-dialog'
import type {
  AppInfo, ExportResult, InterfaceInfo, PacketDetail, PacketRow, ReadSummary, SessionRecord, Settings, Snapshot,
} from './types'

/** Backend errors arrive as plain strings. */
export function errorText(e: unknown): string {
  if (typeof e === 'string') return e
  if (e instanceof Error) return e.message
  return 'Unexpected error'
}

export const api = {
  appInfo: () => invoke<AppInfo>('app_info'),
  listInterfaces: () => invoke<InterfaceInfo[]>('list_interfaces'),
  validateFilter: (filter: string) => invoke<void>('validate_filter', { filter }),
  startCapture: (iface: string, label: string, filter: string) =>
    invoke<void>('start_capture', { interface: iface, label, filter }),
  stopCapture: () => invoke<number | null>('stop_capture'),
  pauseCapture: () => invoke<void>('pause_capture'),
  resumeCapture: () => invoke<void>('resume_capture'),
  clearCapture: () => invoke<void>('clear_capture'),
  getSnapshot: () => invoke<Snapshot>('get_snapshot'),
  getPacket: (no: number) => invoke<PacketDetail | null>('get_packet', { no }),
  getRowsAfter: (after: number, limit: number) => invoke<PacketRow[]>('get_rows_after', { after, limit }),
  setAnalyticsWindow: (seconds: number) => invoke<void>('set_analytics_window', { seconds }),
  getSettings: () => invoke<Settings>('get_settings'),
  saveSettings: (settings: Settings) => invoke<Settings>('save_settings', { settings }),
  exportCapture: (path: string, format: string, selection: number[] | null) =>
    invoke<ExportResult>('export_capture', { path, format, selection }),
  importCapture: (path: string) => invoke<ReadSummary>('import_capture', { path }),
  listSessions: () => invoke<SessionRecord[]>('list_sessions'),
  openSession: (id: number) => invoke<ReadSummary>('open_session', { id }),
  renameSession: (id: number, name: string) => invoke<void>('rename_session', { id, name }),
  deleteSession: (id: number) => invoke<void>('delete_session', { id }),
  exportReport: (path: string, format: string, sessionId: number | null) =>
    invoke<void>('export_report', { path, format, sessionId }),
}

export const dialogs = {
  pickCapture: () =>
    open({ multiple: false, filters: [{ name: 'Packet captures', extensions: ['pcap', 'pcapng', 'cap'] }] }) as Promise<string | null>,
  saveCapture: (format: string, name = 'capture') =>
    save({ defaultPath: `${name}.${format}`, filters: [{ name: format.toUpperCase(), extensions: [format] }] }),
  saveReport: (format: string, name = 'nexus-report') =>
    save({ defaultPath: `${name}.${format}`, filters: [{ name: format.toUpperCase(), extensions: [format] }] }),
}
