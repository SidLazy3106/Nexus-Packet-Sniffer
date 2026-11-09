import { useSyncExternalStore } from 'react'
import { listen } from '@tauri-apps/api/event'
import { api, dialogs, errorText } from './api'
import { CLIENT_MAX_ROWS, CLIENT_TRIM_SLACK, MAX_TOASTS, RESYNC_PAGE_SIZE, TOAST_MS } from './constants'
import type { AppInfo, InterfaceInfo, PacketRow, Settings, Snapshot } from './types'

export type PageId =
  | 'overview' | 'capture' | 'explorer' | 'protocols' | 'rca' | 'analytics' | 'sessions' | 'settings'

export interface Toast { id: number; kind: 'error' | 'success' | 'info'; text: string }

interface AppState {
  page: PageId
  snapshot: Snapshot | null
  appInfo: AppInfo | null
  interfaces: InterfaceInfo[]
  interfacesError: string | null
  interfacesLoading: boolean
  settings: Settings | null
  ifaceName: string | null
  bpfFilter: string
  selectedNo: number | null
  /** Packets ticked in the Live Capture table (multi-select). */
  checked: ReadonlySet<number>
  toasts: Toast[]
  busy: boolean
  /** Packet number to reveal in the explorer / capture table. */
  focusNo: number | null
}

const initial: AppState = {
  page: 'overview',
  snapshot: null,
  appInfo: null,
  interfaces: [],
  interfacesError: null,
  interfacesLoading: false,
  settings: null,
  ifaceName: null,
  bpfFilter: '',
  selectedNo: null,
  checked: new Set(),
  toasts: [],
  busy: false,
  focusNo: null,
}

let state = initial
const listeners = new Set<() => void>()
function set(patch: Partial<AppState>) {
  state = { ...state, ...patch }
  listeners.forEach((l) => l())
}
const subscribe = (l: () => void) => {
  listeners.add(l)
  return () => listeners.delete(l)
}

export function useApp<T>(select: (s: AppState) => T): T {
  return useSyncExternalStore(subscribe, () => select(state))
}
export const getApp = () => state

// ---- packet rows live outside React state: appended in place, UI notified once per frame ----

const pkt = { rows: [] as PacketRow[], version: 0 }
const pktListeners = new Set<() => void>()
let scheduled = false
function notifyPackets() {
  pkt.version++
  if (scheduled) return
  scheduled = true
  requestAnimationFrame(() => {
    scheduled = false
    pktListeners.forEach((l) => l())
  })
}

export const packetStore = {
  get rows() {
    return pkt.rows
  },
  push(batch: PacketRow[]) {
    if (batch.length === 0) return
    // A new capture restarts numbering at 1.
    if (batch[0].no === 1 && pkt.rows.length > 0 && pkt.rows[pkt.rows.length - 1].no >= 1) pkt.rows = []
    for (const r of batch) pkt.rows.push(r)
    if (pkt.rows.length > CLIENT_MAX_ROWS + CLIENT_TRIM_SLACK) pkt.rows = pkt.rows.slice(pkt.rows.length - CLIENT_MAX_ROWS)
    notifyPackets()
  },
  clear() {
    pkt.rows = []
    notifyPackets()
  },
}

export function usePackets(): { rows: PacketRow[]; version: number } {
  const version = useSyncExternalStore(
    (l) => {
      pktListeners.add(l)
      return () => pktListeners.delete(l)
    },
    () => pkt.version,
  )
  return { rows: pkt.rows, version }
}

// ---- actions ----

let toastId = 1
export function notify(kind: Toast['kind'], text: string) {
  const id = toastId++
  set({ toasts: [...state.toasts.slice(-(MAX_TOASTS - 1)), { id, kind, text }] })
  setTimeout(() => dismissToast(id), kind === 'error' ? TOAST_MS.error : TOAST_MS.other)
}
export function dismissToast(id: number) {
  set({ toasts: state.toasts.filter((t) => t.id !== id) })
}

export const setPage = (page: PageId) => set({ page })
export const selectPacket = (no: number | null) => set({ selectedNo: no })
export const setChecked = (checked: ReadonlySet<number>) => set({ checked })
export const setIface = (ifaceName: string | null) => set({ ifaceName })
export const setBpf = (bpfFilter: string) => set({ bpfFilter })
export function revealPacket(no: number, page: PageId = 'explorer') {
  set({ selectedNo: no, focusNo: no, page })
}

async function guard<T>(fn: () => Promise<T>, okMsg?: string): Promise<T | undefined> {
  set({ busy: true })
  try {
    const r = await fn()
    if (okMsg) notify('success', okMsg)
    return r
  } catch (e) {
    notify('error', errorText(e))
    return undefined
  } finally {
    set({ busy: false })
  }
}

export async function refreshInterfaces() {
  set({ interfacesLoading: true, interfacesError: null })
  try {
    const list = await api.listInterfaces()
    const cur = state.ifaceName
    const pick =
      cur && list.some((i) => i.name === cur)
        ? cur
        : (list.find((i) => i.name === state.settings?.default_interface)?.name ??
          list.find((i) => i.status === 'up' && !i.loopback && i.ipv4.length > 0)?.name ??
          list.find((i) => i.status === 'up' && !i.loopback)?.name ??
          list[0]?.name ??
          null)
    set({ interfaces: list, ifaceName: pick, interfacesLoading: false })
  } catch (e) {
    set({ interfaces: [], interfacesError: errorText(e), interfacesLoading: false })
  }
}

export async function startCapture() {
  const { ifaceName, interfaces, bpfFilter } = state
  if (!ifaceName) return notify('error', 'Select a network interface first.')
  const label = interfaces.find((i) => i.name === ifaceName)?.friendly_name ?? ifaceName
  await guard(async () => {
    await api.startCapture(ifaceName, label, bpfFilter)
    packetStore.clear()
    set({ selectedNo: null, checked: new Set() })
  })
}

export async function stopCapture() {
  await guard(async () => {
    const id = await api.stopCapture()
    notify('success', id ? 'Capture stopped and saved as a session.' : 'Capture stopped.')
  })
}

export const pauseCapture = () => guard(() => api.pauseCapture())
export const resumeCapture = () => guard(() => api.resumeCapture())

export async function clearCapture() {
  await guard(async () => {
    await api.clearCapture()
    packetStore.clear()
    set({ selectedNo: null, checked: new Set() })
  })
}

export async function importFile(path?: string) {
  const p = path ?? (await dialogs.pickCapture())
  if (!p) return
  await guard(async () => {
    packetStore.clear()
    set({ selectedNo: null, checked: new Set() })
    const s = await api.importCapture(p)
    notify(
      s.truncated_tail ? 'info' : 'success',
      `Imported ${s.packets.toLocaleString()} packets (${s.format.toUpperCase()})${s.truncated_tail ? ' - the file ended mid-record, so the final packet was ignored.' : ''}`,
    )
    set({ page: 'capture' })
  })
}

export async function openSession(id: number) {
  await guard(async () => {
    packetStore.clear()
    set({ selectedNo: null, checked: new Set() })
    const s = await api.openSession(id)
    notify('success', `Opened session with ${s.packets.toLocaleString()} packets.`)
    set({ page: 'capture' })
  })
}

export async function exportCapture(selection: number[] | null) {
  const fmt = state.settings?.default_export_format ?? 'pcapng'
  const path = await dialogs.saveCapture(fmt)
  if (!path) return
  const format = path.toLowerCase().endsWith('.pcap') ? 'pcap' : 'pcapng'
  await guard(async () => {
    const r = await api.exportCapture(path, format, selection)
    notify('success', `Exported ${r.written.toLocaleString()} packets to ${path}${r.skipped_other_link_type ? ` (${r.skipped_other_link_type} skipped: different link type)` : ''}. Payload bytes beyond the retention setting are not included.`)
  })
}

export async function exportReport(format: 'json' | 'csv', sessionId: number | null = null) {
  const path = await dialogs.saveReport(format)
  if (!path) return
  await guard(() => api.exportReport(path, format, sessionId), `Report saved to ${path}`)
}

export async function loadSettings() {
  const s = await api.getSettings()
  set({ settings: s, bpfFilter: state.bpfFilter || s.default_filter })
}

export async function saveSettings(s: Settings) {
  const saved = await guard(() => api.saveSettings(s), 'Settings saved. Capture parameters apply to the next capture.')
  if (saved) set({ settings: saved })
}

/** Wire up backend events and load initial state. Returns a cleanup function. */
export async function initApp(): Promise<() => void> {
  const un1 = await listen<PacketRow[]>('nexus://packets', (e) => packetStore.push(e.payload))
  const un2 = await listen<Snapshot>('nexus://snapshot', (e) => set({ snapshot: e.payload }))
  try {
    const [info, snap] = await Promise.all([api.appInfo(), api.getSnapshot()])
    set({ appInfo: info, snapshot: snap })
    await loadSettings()
    // Resynchronise rows if the webview reloaded while packets were retained in the backend.
    if (snap.buffered_packets > 0 && pkt.rows.length === 0) {
      let after = 0
      for (;;) {
        const rows = await api.getRowsAfter(after, RESYNC_PAGE_SIZE)
        if (rows.length === 0) break
        packetStore.push(rows)
        after = rows[rows.length - 1].no
      }
    }
  } catch (e) {
    notify('error', errorText(e))
  }
  await refreshInterfaces()
  return () => {
    un1()
    un2()
  }
}
