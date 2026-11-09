import { describe, expect, it } from 'vitest'
import { matchesFilter, parseTerms } from './filter'
import type { PacketRow } from './types'

const row = (p: Partial<PacketRow>): PacketRow => ({
  no: 1, ts_us: 0, src: '10.0.0.1', dst: '10.0.0.2', sport: 51000, dport: 443, protocol: 'TCP',
  length: 60, info: '51000 → 443 [SYN]', anomaly: false, flags: 'SYN', ...p,
})
const m = (r: PacketRow, text: string, protos: string[] = []) => matchesFilter(r, parseTerms(text), new Set(protos))

describe('display filter', () => {
  it('matches everything when empty', () => expect(m(row({}), '')).toBe(true))
  it('matches by port exactly', () => {
    expect(m(row({}), 'port:443')).toBe(true)
    expect(m(row({}), 'port:44')).toBe(false)
    expect(m(row({}), '443')).toBe(true)
  })
  it('matches ip exactly, not by substring', () => {
    expect(m(row({}), 'ip:10.0.0.1')).toBe(true)
    expect(m(row({}), 'ip:10.0.0')).toBe(false)
  })
  it('ANDs terms and supports exclusion', () => {
    expect(m(row({}), '10.0.0.2 syn')).toBe(true)
    expect(m(row({}), '10.0.0.2 -syn')).toBe(false)
    expect(m(row({}), '-dns')).toBe(true)
  })
  it('filters by protocol set', () => {
    expect(m(row({}), '', ['TCP'])).toBe(true)
    expect(m(row({}), '', ['UDP', 'DNS'])).toBe(false)
  })
  it('treats IPv6 text as plain text', () => {
    const r = row({ src: 'fe80::1', dst: 'ff02::2', protocol: 'ICMPv6', sport: null, dport: null })
    expect(m(r, 'fe80::1')).toBe(true)
    expect(m(r, 'fe80:')).toBe(true)
    expect(m(r, 'ip:fe80::1')).toBe(true)
  })
})
