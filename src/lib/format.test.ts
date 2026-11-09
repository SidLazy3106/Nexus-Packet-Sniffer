import { describe, expect, it } from 'vitest'
import { endpoint, fmtBytes, fmtDuration, fmtMs, fmtPps, fmtRate, pct } from './format'

describe('formatters', () => {
  it('formats bytes with binary units', () => {
    expect(fmtBytes(0)).toBe('0 B')
    expect(fmtBytes(1023)).toBe('1023 B')
    expect(fmtBytes(1024)).toBe('1.0 KB')
    expect(fmtBytes(1536 * 1024)).toBe('1.5 MB')
    expect(fmtBytes(-5)).toBe('0 B')
    expect(fmtBytes(Number.NaN)).toBe('0 B')
  })

  it('formats rates in bits per second from bytes per second', () => {
    expect(fmtRate(0)).toBe('0 bps')
    expect(fmtRate(125)).toBe('1.0 Kbps')
    expect(fmtRate(125_000)).toBe('1.00 Mbps')
    expect(fmtRate(125_000_000)).toBe('1.00 Gbps')
  })

  it('formats packet rates', () => {
    expect(fmtPps(7)).toBe('7.0')
    expect(fmtPps(1234.6)).toBe('1,235')
  })

  it('formats durations', () => {
    expect(fmtDuration(0)).toBe('0s')
    expect(fmtDuration(63_000)).toBe('1m 3s')
    expect(fmtDuration(3_723_000)).toBe('1h 2m 3s')
  })

  it('formats latency with sensible precision', () => {
    expect(fmtMs(0.25)).toBe('0.250 ms')
    expect(fmtMs(12.34)).toBe('12.3 ms')
    expect(fmtMs(250.6)).toBe('251 ms')
  })

  it('brackets IPv6 endpoints and tolerates missing ports', () => {
    expect(endpoint('10.0.0.1', 443)).toBe('10.0.0.1:443')
    expect(endpoint('fe80::1', 53)).toBe('[fe80::1]:53')
    expect(endpoint('10.0.0.1', null)).toBe('10.0.0.1')
    expect(endpoint('', 80)).toBe('-')
  })

  it('computes percentages safely', () => {
    expect(pct(1, 4)).toBe('25.0%')
    expect(pct(1, 0)).toBe('0%')
  })
})
