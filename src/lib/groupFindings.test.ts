import { describe, expect, it } from 'vitest'
import { groupFindings } from './groupFindings'
import type { Finding, Severity } from './types'

const f = (id: string, title: string, severity: Severity, count = 1, last = 0): Finding => ({
  id, title, severity, confidence: 'High', category: 'tcp', protocol: 'TCP', first_ts_us: 0, last_ts_us: last,
  count, description: '', evidence: [], measurements: [], possible_causes: [], recommendations: [], limitations: [], flow: null,
})

describe('groupFindings', () => {
  it('returns nothing for no findings', () => expect(groupFindings([])).toEqual([]))

  it('groups by title and sums occurrence counts', () => {
    const g = groupFindings([f('a', 'Retrans', 'Low', 3), f('b', 'Retrans', 'Low', 4), f('c', 'Reset', 'Low', 1)])
    expect(g).toHaveLength(2)
    expect(g.find((x) => x.title === 'Retrans')).toMatchObject({ total: 7 })
    expect(g.find((x) => x.title === 'Retrans')?.items).toHaveLength(2)
  })

  it('orders members worst-first, then most recent', () => {
    const g = groupFindings([f('a', 'T', 'Low', 1, 5), f('b', 'T', 'High', 1, 1), f('c', 'T', 'Low', 1, 9)])
    expect(g[0].items.map((x) => x.id)).toEqual(['b', 'c', 'a'])
  })

  it('orders groups by their worst member, then by volume', () => {
    const g = groupFindings([f('a', 'Minor', 'Low', 50), f('b', 'Serious', 'High', 1), f('c', 'Other', 'Low', 60)])
    expect(g.map((x) => x.title)).toEqual(['Serious', 'Other', 'Minor'])
  })

  it('does not mutate its input', () => {
    const input = [f('a', 'T', 'Low'), f('b', 'T', 'High')]
    groupFindings(input)
    expect(input.map((x) => x.id)).toEqual(['a', 'b'])
  })
})
