import { describe, expect, it } from 'vitest'
import { ago, daysLeft, isPending, verdictOf } from './format'

describe('format', () => {
  const now = new Date('2026-11-14T10:00:00Z').getTime()
  it('affiche une durée relative', () => {
    expect(ago('2026-11-14T09:59:30Z', now)).toBe('il y a 30 s')
    expect(ago('2026-11-14T09:56:00Z', now)).toBe('il y a 4 min')
    expect(ago('2026-11-13T09:00:00Z', now)).toBe('hier')
    expect(ago(null, now)).toBe('jamais')
  })
  it('compte les jours restants', () => {
    expect(daysLeft('2026-11-19T10:00:00Z', now)).toBe(5)
    expect(daysLeft(null, now)).toBeNull()
  })
  it('libelle les verdicts', () => {
    expect(verdictOf('proved')).toBe('Prouvé vulnérable')
    expect(verdictOf('')).toBe('Aucun check')
  })
  it('repère un check en cours', () => {
    expect(isPending({ status: 'waiting' })).toBe(true)
    expect(isPending({ status: 'done' })).toBe(false)
  })
})
