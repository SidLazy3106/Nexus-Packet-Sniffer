export function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`
}

export function fmtRate(bytesPerSec: number): string {
  const bits = bytesPerSec * 8
  if (bits >= 1e9) return `${(bits / 1e9).toFixed(2)} Gbps`
  if (bits >= 1e6) return `${(bits / 1e6).toFixed(2)} Mbps`
  if (bits >= 1e3) return `${(bits / 1e3).toFixed(1)} Kbps`
  return `${bits.toFixed(0)} bps`
}

export function fmtInt(n: number): string {
  return Math.round(n).toLocaleString('en-US')
}

export function fmtPps(n: number): string {
  return n >= 100 ? fmtInt(n) : n.toFixed(1)
}

/** Clock time with millisecond precision from microseconds since the epoch. */
export function fmtTime(tsUs: number): string {
  const d = new Date(tsUs / 1000)
  const p = (v: number, w = 2) => String(v).padStart(w, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`
}

export function fmtDateTime(ms: number): string {
  if (!ms) return '-'
  return new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'medium' })
}

export function fmtDuration(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const sec = s % 60
  return h ? `${h}h ${m}m ${sec}s` : m ? `${m}m ${sec}s` : `${sec}s`
}

export function fmtMs(v: number): string {
  return v >= 100 ? `${v.toFixed(0)} ms` : v >= 1 ? `${v.toFixed(1)} ms` : `${v.toFixed(3)} ms`
}

export function endpoint(addr: string, port: number | null): string {
  if (!addr) return '-'
  if (port === null) return addr
  return addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`
}

export function pct(part: number, total: number): string {
  return total > 0 ? `${((part / total) * 100).toFixed(1)}%` : '0%'
}
