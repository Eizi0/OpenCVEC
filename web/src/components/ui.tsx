import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { api } from '../api'
import { callbackLabel, verdictLabel, verdictTone } from '../format'
import { getLang, setLang } from '../i18n'

/** Charge une ressource, avec rechargement manuel et rafraîchissement périodique optionnel. */
export function useLoad<T>(path: string | null, intervalMs = 0) {
  const [data, setData] = useState<T | null>(null)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const seq = useRef(0)
  const reload = useCallback(async () => {
    if (!path) return
    const n = ++seq.current
    try {
      const d = await api<T>(path)
      if (n === seq.current) {
        setData(d)
        setError('')
      }
    } catch (e) {
      if (n === seq.current) setError((e as Error).message)
    } finally {
      if (n === seq.current) setLoading(false)
    }
  }, [path])
  useEffect(() => {
    setLoading(true)
    void reload()
    if (!intervalMs) return
    const t = setInterval(() => void reload(), intervalMs)
    return () => clearInterval(t)
  }, [reload, intervalMs])
  return { data, error, loading, reload, setData }
}

export function Logo({ size = 30 }: { size?: number }) {
  return <img src="/logo-192.png" width={size} height={size} alt="" aria-hidden="true" style={{ borderRadius: Math.round(size / 5), display: 'block' }} />
}

export function VerdictPill({ v }: { v: string }) {
  return <span className={`pill ${verdictTone[v] ?? 'gray'}`}>{verdictLabel[v] ?? v}</span>
}

export function CallbackPill({ s }: { s: string }) {
  const tone = s === 'honeytoken' ? 'red' : s === 'correlated' ? 'green' : s === 'duplicate' || s === 'selftest' ? 'blue' : 'gray'
  return <span className={`pill ${tone}`}>{callbackLabel[s] ?? s}</span>
}

export function ModePill({ mode }: { mode: string }) {
  return mode === 'canary' ? <span className="pill yellow">Canari</span> : <span className="pill purple">Empreinte</span>
}

export function SourcePill({ source, version, publisher, signed = true }: { source: string; version?: string; publisher?: string; signed?: boolean }) {
  if (source !== 'plugin') return <span className="pill gray">Intégré</span>
  return <span className={`pill ${signed ? 'blue' : 'red'}`} title={publisher}>Plugin v{version}{publisher ? ` · ${publisher}` : ' · non signé'}</span>
}

export function ErrorBox({ error }: { error: string }) {
  if (!error) return null
  return (
    <div className="notice err" role="alert">
      <strong>Erreur</strong>
      <span>{error}</span>
    </div>
  )
}

export function Loading() {
  return <p className="muted" role="status">Chargement…</p>
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>
}

export function Tabs<T extends string>({ value, onChange, items, label }: { value: T; onChange: (v: T) => void; items: [T, string][]; label: string }) {
  return (
    <div className="tabs" role="group" aria-label={label}>
      {items.map(([id, text]) => (
        <button key={id} type="button" className={value === id ? 'on' : ''} aria-pressed={value === id} onClick={() => onChange(id)}>
          {text}
        </button>
      ))}
    </div>
  )
}

export function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      className="btn small"
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setDone(true)
          setTimeout(() => setDone(false), 1500)
        })
      }}
    >
      {done ? 'Copié' : 'Copier'}
    </button>
  )
}

/** Bascule français / anglais (la page est rechargée). */
export function LangSwitch() {
  const lang = getLang()
  return (
    <button type="button" className="btn small" data-no-i18n onClick={() => setLang(lang === 'fr' ? 'en' : 'fr')}
      aria-label={lang === 'fr' ? 'Switch to English' : 'Passer en français'}>
      {lang === 'fr' ? 'English' : 'Français'}
    </button>
  )
}
