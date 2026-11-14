import { getLang } from './i18n'
import type { Verdict } from './types'

export const verdictLabel: Record<string, string> = {
  proved: 'Prouvé vulnérable',
  probable: 'Probable',
  exposed: 'Exposé',
  patched: 'Version corrigée',
  inconclusive: 'Non concluant',
  error: 'Erreur',
  '': 'Aucun check',
}

export const verdictTone: Record<string, string> = {
  proved: 'red',
  probable: 'orange',
  exposed: 'orange',
  patched: 'green',
  inconclusive: 'blue',
  error: 'gray',
  '': 'gray',
}

export const statusLabel: Record<string, string> = {
  queued: 'En file',
  running: 'Envoi',
  waiting: 'En attente du canari',
  done: 'Terminé',
  error: 'Erreur',
  cancelled: 'Annulé',
}

export const callbackLabel: Record<string, string> = {
  correlated: 'Corrélé',
  duplicate: 'Doublon',
  expired: 'Rejeté (expiré)',
  replay: 'Rejeté (rejeu)',
  unknown: 'Rejeté (jeton inconnu)',
  selftest: 'Auto-test',
  honeytoken: 'Alerte : canari fichier lu hors check',
}

export const proofMethodLabel: Record<string, string> = {
  dns_txt: 'DNS TXT',
  well_known: '/.well-known',
  allowlist: 'Liste blanche admin',
}

export const kindLabel: Record<string, string> = { domain: 'Domaine', ip: 'Adresse IP', cidr: 'Plage' }

export const roleLabel: Record<string, string> = { admin: 'Administrateur', analyst: 'Analyste', viewer: 'Lecteur' }

const locale = getLang() === 'en' ? 'en-GB' : 'fr-FR'
const dtf = new Intl.DateTimeFormat(locale, { dateStyle: 'short', timeStyle: 'medium' })
const df = new Intl.DateTimeFormat(locale, { dateStyle: 'short' })

export function dateTime(s: string | null | undefined): string {
  if (!s) return '—'
  return dtf.format(new Date(s))
}

export function date(s: string | null | undefined): string {
  if (!s) return '—'
  return df.format(new Date(s))
}

export function ago(s: string | null | undefined, now = Date.now()): string {
  if (!s) return 'jamais'
  const d = Math.round((now - new Date(s).getTime()) / 1000)
  if (d < 0) return 'à l’instant'
  if (d < 60) return `il y a ${d} s`
  if (d < 3600) return `il y a ${Math.floor(d / 60)} min`
  if (d < 86400) return `il y a ${Math.floor(d / 3600)} h`
  const days = Math.floor(d / 86400)
  return days === 1 ? 'hier' : `il y a ${days} j`
}

export function daysLeft(s: string | null | undefined, now = Date.now()): number | null {
  if (!s) return null
  return Math.ceil((new Date(s).getTime() - now) / 86400000)
}

export function isPending(v: { status: string }) {
  return v.status === 'queued' || v.status === 'running' || v.status === 'waiting'
}

export function verdictOf(v: Verdict | undefined) {
  return verdictLabel[v ?? ''] ?? v
}
