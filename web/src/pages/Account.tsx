import { useState, type FormEvent } from 'react'
import { post } from '../api'
import { useAuth } from '../auth'
import { ErrorBox } from '../components/ui'
import { roleLabel } from '../format'

export function Account() {
  const { me, refresh } = useAuth()
  const [cur, setCur] = useState('')
  const [next, setNext] = useState('')
  const [pwMsg, setPwMsg] = useState('')
  const [pwErr, setPwErr] = useState('')
  const [setup, setSetup] = useState<{ secret: string; uri: string; qr?: string } | null>(null)
  const [code, setCode] = useState('')
  const [mfaErr, setMfaErr] = useState('')
  const [disablePw, setDisablePw] = useState('')

  async function changePw(e: FormEvent) {
    e.preventDefault()
    setPwErr('')
    setPwMsg('')
    try {
      await post('/api/me/password', { current: cur, new: next })
      setCur('')
      setNext('')
      setPwMsg('Mot de passe modifié. Vos autres sessions ont été fermées.')
    } catch (e2) {
      setPwErr((e2 as Error).message)
    }
  }
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Mon compte</h1>
          <p className="lead">{me.user.email} · {roleLabel[me.user.role]}</p>
        </div>
      </header>
      {me.require_mfa && !me.user.totp_enabled && (
        <div className="notice warn" role="alert"><strong>Double authentification obligatoire</strong><span>Activez-la ci-dessous pour accéder au reste de l'application.</span></div>
      )}
      <div className="row">
        <section className="card col-1">
          <h2>Double authentification (TOTP)</h2>
          {me.user.totp_enabled ? (
            <form className="stack" style={{ gap: 12 }} onSubmit={async (e) => {
              e.preventDefault()
              setMfaErr('')
              try { await post('/api/me/mfa/disable', { password: disablePw }); await refresh() } catch (e2) { setMfaErr((e2 as Error).message) }
            }}>
              <p className="muted" style={{ margin: 0 }}><span className="pill green">Activée</span> Un code est demandé à chaque connexion.</p>
              {!me.require_mfa && (
                <>
                  <div className="field"><label htmlFor="dpw">Mot de passe pour désactiver</label><input id="dpw" className="input" type="password" value={disablePw} onChange={(e) => setDisablePw(e.target.value)} /></div>
                  <ErrorBox error={mfaErr} />
                  <div className="btns"><button className="btn danger" type="submit">Désactiver</button></div>
                </>
              )}
            </form>
          ) : !setup ? (
            <>
              <p className="muted" style={{ margin: 0 }}>Protégez votre compte avec une application d'authentification (Aegis, 2FAS, Google Authenticator…).</p>
              <ErrorBox error={mfaErr} />
              <div className="btns"><button className="btn primary" type="button" onClick={async () => {
                try { setSetup(await post('/api/me/mfa/setup')) } catch (e) { setMfaErr((e as Error).message) }
              }}>Configurer</button></div>
            </>
          ) : (
            <form className="stack" style={{ gap: 12 }} onSubmit={async (e) => {
              e.preventDefault()
              setMfaErr('')
              try { await post('/api/me/mfa/enable', { code }); setSetup(null); await refresh() } catch (e2) { setMfaErr((e2 as Error).message) }
            }}>
              {setup.qr && <img src={setup.qr} alt="QR code à scanner avec l'application d'authentification" width={180} height={180} style={{ background: '#fff', padding: 8, borderRadius: 8, imageRendering: 'pixelated' }} />}
              <span className="small muted">Ou saisissez la clé : <span className="mono break">{setup.secret}</span></span>
              <div className="field"><label htmlFor="tc">Code affiché</label><input id="tc" className="input mono" inputMode="numeric" autoComplete="one-time-code" value={code} onChange={(e) => setCode(e.target.value)} /></div>
              <ErrorBox error={mfaErr} />
              <div className="btns"><button className="btn primary" type="submit">Activer</button></div>
            </form>
          )}
        </section>
        <form className="card col-1" onSubmit={changePw}>
          <h2>Mot de passe</h2>
          <div className="field"><label htmlFor="cpw">Mot de passe actuel</label><input id="cpw" className="input" type="password" autoComplete="current-password" required value={cur} onChange={(e) => setCur(e.target.value)} /></div>
          <div className="field"><label htmlFor="npw">Nouveau mot de passe (12 caractères minimum)</label><input id="npw" className="input" type="password" autoComplete="new-password" minLength={12} required value={next} onChange={(e) => setNext(e.target.value)} /></div>
          <ErrorBox error={pwErr} />
          {pwMsg && <div className="notice ok"><strong>{pwMsg}</strong></div>}
          <div className="btns"><button className="btn primary" type="submit">Modifier</button></div>
        </form>
      </div>
    </>
  )
}
