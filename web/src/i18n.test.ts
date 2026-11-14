import { describe, expect, it } from 'vitest'
import { _test } from './i18n'

describe('i18n', () => {
  it('traduit les textes exacts en conservant les espaces', () => {
    expect(_test.translate("Vue d'ensemble")).toBe('Overview')
    expect(_test.translate('  Prouvé vulnérable ')).toBe('  Proven vulnerable ')
  })
  it('traduit les textes à variables', () => {
    expect(_test.translate('il y a 4 min')).toBe('4 min ago')
    expect(_test.translate('Prouvée · 21 j restants')).toBe('Proven · 21 days left')
    expect(_test.translate('Lancer 2 checks')).toBe('Launch 2 check(s)')
  })
  it('laisse intacts les textes inconnus (données utilisateur)', () => {
    expect(_test.translate('erp.exemple.fr')).toBeNull()
  })
})
