// Frontend tuning values, named in one place.

/** Rows fetched per request when the UI re-synchronises with packets retained in the backend. */
export const RESYNC_PAGE_SIZE = 20_000
/** Sorted views that need a full re-sort update at most this often while packets stream in. */
export const SORT_THROTTLE_MS = 500
/** Wait after the last keystroke before a BPF filter is validated by the backend. */
export const BPF_DEBOUNCE_MS = 400
/** How long toasts stay visible. */
export const TOAST_MS = { error: 12_000, other: 5_000 } as const
/** Toasts shown at once. */
export const MAX_TOASTS = 4
/** Packet table row height in px (fixed so the list can be virtualised). */
export const PACKET_ROW_HEIGHT = 26
/** Packets kept in the browser; older rows are dropped from the table (the backend keeps its own ring). */
export const CLIENT_MAX_ROWS = 250_000
/** Rows trimmed in one go once the limit is exceeded, so trimming is not done per packet. */
export const CLIENT_TRIM_SLACK = 10_000
