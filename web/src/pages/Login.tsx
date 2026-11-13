import { useState, type FormEvent } from 'react'
import { post } from '../api'
import { Logo } from '../components/ui'

export function Login({ onDone }: { onDone: () => void }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [mfa, setMfa] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      if (!mfa) {
        const r = await post<{ mfa_required: boolean }>('/api/login', { email, password })
        if (r.mfa_required) {
          setMfa(true)
          return
        }
      } else {
        await post('/api/login/totp', { code })
      }
      onDone()
    } catch (err) {
      setError((err as Error).message)
      if (mfa && /expirée|recommencez/.test((err as Error).message)) setMfa(false)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="login">
      <section className="login-side">
        <div className="brand" style={{ fontSize: 24, padding: 0 }}>
          <Logo size={40} />
          <span>OpenCVEC</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 520 }}>
          <h1>Prouvez votre exposition.<br />Sans rien exploiter.</h1>
          <p style={{ margin: 0, fontSize: 16, lineHeight: 1.6, color: '#aeb7c4' }}>
            Chaque check pousse la cible à appeler un canari unique, lié à un asset dont vous avez prouvé la propriété. Pas de shell, pas de charge modifiable : un appel DNS ou HTTP suffit comme preuve.
          </p>
          <ol style={{ margin: 0, padding: 0, listStyle: 'none', display: 'flex', flexDirection: 'column', gap: 12, fontSize: 14, color: 'var(--text-2)' }}>
            {['Prouver la propriété de l’asset (TXT, /.well-known ou liste blanche)', 'Émettre un canari à usage unique pour ce check', 'Recevoir le callback : verdict et preuve horodatée'].map((t, i) => (
              <li key={t} style={{ display: 'flex', gap: 12, alignItems: 'baseline' }}>
                <span className="mono" style={{ color: 'var(--accent)' }}>0{i + 1}</span>
                {t}
              </li>
            ))}
          </ol>
        </div>
        <span className="small dim">Instance auto-hébergée · v0.1.0</span>
      </section>
      <section className="login-form">
        <form onSubmit={submit}>
          <h2 style={{ fontFamily: 'var(--display)', fontSize: 26 }}>{mfa ? 'Double authentification' : 'Connexion'}</h2>
          {!mfa ? (
            <>
              <div className="field">
                <label htmlFor="email">Adresse e-mail</label>
                <input id="email" className="input" type="email" autoComplete="username" required value={email} onChange={(e) => setEmail(e.target.value)} />
              </div>
              <div className="field">
                <label htmlFor="pwd">Mot de passe</label>
                <input id="pwd" className="input" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
              </div>
            </>
          ) : (
            <div className="field">
              <label htmlFor="otp">Code TOTP</label>
              <input id="otp" className="input mono" inputMode="numeric" autoComplete="one-time-code" placeholder="6 chiffres" autoFocus required value={code}
                onChange={(e) => setCode(e.target.value)} style={{ letterSpacing: 4, fontSize: 15 }} />
            </div>
          )}
          {error && <p role="alert" style={{ margin: 0, color: 'var(--red)', fontSize: 13.5 }}>{error}</p>}
          <button className="btn primary" type="submit" disabled={busy} style={{ minHeight: 46, fontSize: 15 }}>
            {busy ? 'Vérification…' : mfa ? 'Valider' : 'Se connecter'}
          </button>
          <p className="hint">Toute action est inscrite au journal d'audit. L'usage est limité aux assets dont votre organisation a prouvé la propriété.</p>
        </form>
      </section>
    </div>
  )
}
