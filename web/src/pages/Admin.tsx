import { useEffect, useState, type FormEvent } from 'react'
import { del, post, put } from '../api'
import { useAuth } from '../auth'
import { CopyButton, ErrorBox, Loading, useLoad } from '../components/ui'
import { dateTime, daysLeft, roleLabel } from '../format'
import type { AllowRow, Receiver, Role, Settings, UserRow } from '../types'

type Tab = 'users' | 'allow' | 'recv'

export function Admin() {
  const [tab, setTab] = useState<Tab>('users')
  return (
    <>
      <h1>Administration</h1>
      <div role="tablist" aria-label="Sections" className="tabline">
        {([['users', 'Utilisateurs et rôles'], ['allow', 'Liste blanche réseau interne'], ['recv', 'Récepteur canari et limites']] as [Tab, string][]).map(([id, l]) => (
          <button key={id} type="button" role="tab" aria-selected={tab === id} className={tab === id ? 'on' : ''} onClick={() => setTab(id)}>{l}</button>
        ))}
      </div>
      {tab === 'users' && <Users />}
      {tab === 'allow' && <Allowlist />}
      {tab === 'recv' && <ReceiverAdmin />}
    </>
  )
}

function Secret({ label, value }: { label: string; value: string }) {
  return (
    <div className="notice warn" role="status">
      <strong>{label}</strong>
      <div className="btns"><span className="mono" style={{ fontSize: 14 }}>{value}</span><CopyButton text={value} /></div>
      <span className="small muted">Communiquez-le par un canal sûr : il ne sera plus affiché.</span>
    </div>
  )
}

function Users() {
  const { me } = useAuth()
  const { data, error, reload } = useLoad<UserRow[]>('/api/users')
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [role, setRole] = useState<Role>('analyst')
  const [err, setErr] = useState('')
  const [secret, setSecret] = useState<{ label: string; value: string } | null>(null)

  async function create(e: FormEvent) {
    e.preventDefault()
    setErr('')
    try {
      const r = await post<{ password?: string }>('/api/users', { email, name, role })
      if (r.password) setSecret({ label: `Mot de passe initial de ${email}`, value: r.password })
      setEmail('')
      setName('')
      await reload()
    } catch (e2) {
      setErr((e2 as Error).message)
    }
  }
  async function update(u: UserRow, patch: Partial<UserRow>) {
    setErr('')
    try {
      await put(`/api/users/${u.id}`, { name: u.name, role: patch.role ?? u.role, disabled: patch.disabled ?? u.disabled })
      await reload()
    } catch (e) {
      setErr((e as Error).message)
    }
  }
  return (
    <section className="stack">
      <p className="lead">Administrateur : tout. Analyste : assets, checks, rapports. Lecteur : consultation seule.</p>
      <form className="card" onSubmit={create} style={{ flexDirection: 'row', flexWrap: 'wrap', alignItems: 'flex-end', gap: 12 }}>
        <div className="field" style={{ flex: '2 1 220px' }}><label htmlFor="ue">E-mail</label><input id="ue" className="input" type="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></div>
        <div className="field" style={{ flex: '1 1 160px' }}><label htmlFor="un">Nom</label><input id="un" className="input" value={name} onChange={(e) => setName(e.target.value)} /></div>
        <div className="field" style={{ flex: '1 1 160px' }}><label htmlFor="ur">Rôle</label>
          <select id="ur" className="input" value={role} onChange={(e) => setRole(e.target.value as Role)}>
            <option value="analyst">Analyste</option><option value="viewer">Lecteur</option><option value="admin">Administrateur</option>
          </select></div>
        <button className="btn primary" type="submit">Créer le compte</button>
      </form>
      {secret && <Secret {...secret} />}
      <ErrorBox error={err || error} />
      {!data ? <Loading /> : (
        <div className="card flush table-wrap">
          <table className="t" style={{ minWidth: 820 }}>
            <thead><tr><th>Utilisateur</th><th>Rôle</th><th>TOTP</th><th>Dernière connexion</th><th>Actions</th></tr></thead>
            <tbody>
              {data.map((u) => (
                <tr key={u.id} style={{ opacity: u.disabled ? 0.55 : 1 }}>
                  <td>{u.name || u.email}<div className="sub">{u.email}{u.disabled ? ' · désactivé' : ''}</div></td>
                  <td>
                    <label className="sr-only" htmlFor={`role-${u.id}`}>Rôle de {u.email}</label>
                    <select id={`role-${u.id}`} className="input" style={{ minHeight: 36, width: 'auto' }} value={u.role} disabled={u.id === me.user.id} onChange={(e) => void update(u, { role: e.target.value as Role })}>
                      {(['admin', 'analyst', 'viewer'] as Role[]).map((r) => <option key={r} value={r}>{roleLabel[r]}</option>)}
                    </select>
                  </td>
                  <td style={{ color: u.totp_enabled ? 'var(--green)' : 'var(--accent)' }}>{u.totp_enabled ? 'Activé' : 'À configurer'}</td>
                  <td className="muted">{dateTime(u.last_login_at)}</td>
                  <td>
                    {u.id !== me.user.id && (
                      <div className="btns" style={{ gap: 6 }}>
                        <button className="btn small" type="button" onClick={() => void update(u, { disabled: !u.disabled })}>{u.disabled ? 'Réactiver' : 'Désactiver'}</button>
                        <button className="btn small" type="button" onClick={async () => {
                          if (!window.confirm(`Réinitialiser l'accès de ${u.email} ? Nouveau mot de passe, double authentification à refaire.`)) return
                          try {
                            const r = await post<{ password: string }>(`/api/users/${u.id}/reset`)
                            setSecret({ label: `Nouveau mot de passe de ${u.email}`, value: r.password })
                            await reload()
                          } catch (e) { setErr((e as Error).message) }
                        }}>Réinitialiser</button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function Allowlist() {
  const { data, error, reload } = useLoad<AllowRow[]>('/api/allowlist')
  const [cidr, setCidr] = useState('')
  const [reason, setReason] = useState('')
  const [review, setReview] = useState(30)
  const [err, setErr] = useState('')
  async function add(e: FormEvent) {
    e.preventDefault()
    setErr('')
    try {
      await post('/api/allowlist', { cidr, reason, review_days: review })
      setCidr('')
      setReason('')
      await reload()
    } catch (e2) {
      setErr((e2 as Error).message)
    }
  }
  return (
    <section className="stack">
      <p className="lead">Les adresses privées ne peuvent pas prouver leur propriété par DNS public. Seul un administrateur peut les autoriser : un motif est exigé et une revue a lieu au plus tous les 90 jours. Une plage expirée ou retirée invalide les preuves qui en dépendent.</p>
      <form className="card" onSubmit={add} style={{ flexDirection: 'row', flexWrap: 'wrap', alignItems: 'flex-end', gap: 12 }}>
        <div className="field" style={{ flex: '1 1 200px' }}><label htmlFor="ac">Plage CIDR</label><input id="ac" className="input mono" required placeholder="10.30.0.0/24" value={cidr} onChange={(e) => setCidr(e.target.value)} /></div>
        <div className="field" style={{ flex: '2 1 280px' }}><label htmlFor="ar">Motif</label><input id="ar" className="input" required placeholder="Ex. : serveurs applicatifs du site de Lyon" value={reason} onChange={(e) => setReason(e.target.value)} /></div>
        <div className="field" style={{ flex: '0 1 140px' }}><label htmlFor="ad">Revue (jours)</label><input id="ad" className="input" type="number" min={1} max={90} value={review} onChange={(e) => setReview(Number(e.target.value))} /></div>
        <button className="btn primary" type="submit">Autoriser</button>
      </form>
      <ErrorBox error={err || error} />
      {!data ? <Loading /> : (
        <div className="card flush table-wrap">
          <table className="t" style={{ minWidth: 720 }}>
            <thead><tr><th>Plage</th><th>Motif</th><th>Ajoutée par</th><th>Revue</th><th>Actions</th></tr></thead>
            <tbody>
              {data.length === 0 && <tr><td colSpan={5} className="muted" style={{ textAlign: 'center', padding: 28 }}>Aucune plage autorisée.</td></tr>}
              {data.map((r) => {
                const d = daysLeft(r.review_at) ?? 0
                return (
                  <tr key={r.id}>
                    <td className="mono">{r.cidr}</td>
                    <td style={{ color: 'var(--text-2)' }}>{r.reason}</td>
                    <td>{r.added_by}<div className="sub">{dateTime(r.created_at)}</div></td>
                    <td style={{ color: d <= 0 ? 'var(--red)' : d <= 7 ? 'var(--accent)' : 'var(--muted)' }}>{d <= 0 ? 'expirée' : `dans ${d} j`}</td>
                    <td><div className="btns" style={{ gap: 6 }}>
                      <button className="btn small" type="button" onClick={async () => { try { await post(`/api/allowlist/${r.id}/renew`); await reload() } catch (e) { setErr((e as Error).message) } }}>Prolonger 30 j</button>
                      <button className="btn small danger" type="button" onClick={async () => {
                        if (!window.confirm(`Retirer ${r.cidr} ? Les assets prouvés par cette plage perdront leur preuve.`)) return
                        try { await del(`/api/allowlist/${r.id}`); await reload() } catch (e) { setErr((e as Error).message) }
                      }}>Retirer</button>
                    </div></td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function ReceiverAdmin() {
  const { data: rcv } = useLoad<Receiver>('/api/receiver')
  const { data: st, setData } = useLoad<Settings>('/api/settings')
  const [form, setForm] = useState<Settings | null>(null)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const [test, setTest] = useState<{ ok: boolean; steps: { name: string; ok: boolean; detail: string }[] } | null>(null)
  const [testing, setTesting] = useState(false)
  useEffect(() => { if (st && !form) setForm(st) }, [st, form])

  async function save(e: FormEvent) {
    e.preventDefault()
    setErr('')
    setMsg('')
    try {
      setData(await put<Settings>('/api/settings', form))
      setMsg('Réglages enregistrés.')
    } catch (e2) {
      setErr((e2 as Error).message)
    }
  }
  const num = (k: Exclude<keyof Settings, 'allow_unsigned_plugins'>) => ({
    value: form?.[k] ?? 0,
    onChange: (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...(form as Settings), [k]: Number(e.target.value) }),
  })
  return (
    <div className="row">
      <div className="col-2 stack">
        <section className="card">
          <h2>Zone canari déléguée</h2>
          {rcv ? (
            <>
              <div className="kv"><span>Zone</span><span className="mono">{rcv.zone}</span></div>
              <div className="kv"><span>Serveur de noms annoncé</span><span className="mono">{rcv.ns_name}</span></div>
              <div className="kv"><span>Adresse du récepteur</span><span className="mono">{rcv.ip}</span></div>
              <span className="label">Enregistrements à créer dans la zone parente</span>
              <pre className="code">{rcv.records.join('\n')}</pre>
              <p className="hint">Se règle par variables d'environnement (OPENCVEC_CANARY_ZONE, OPENCVEC_CANARY_IP, OPENCVEC_NS_NAME). Les ports 53 (UDP et TCP) et 80 doivent être joignables depuis Internet.</p>
            </>
          ) : <Loading />}
        </section>
        <form className="card" onSubmit={save}>
          <h2>Canaris, limites et plugins</h2>
          {form ? (
            <div className="row" style={{ gap: 14 }}>
              <div className="field" style={{ flex: '1 1 180px' }}><label htmlFor="ttl">Durée de vie du canari (min)</label><input id="ttl" className="input" type="number" min={5} max={60} {...num('canary_ttl_minutes')} /></div>
              <div className="field" style={{ flex: '1 1 180px' }}><label htmlFor="wait">Attente du callback (s)</label><input id="wait" className="input" type="number" min={15} max={600} {...num('wait_seconds')} /></div>
              <div className="field" style={{ flex: '1 1 180px' }}><label htmlFor="cpa">Checks par asset et par jour</label><input id="cpa" className="input" type="number" min={1} max={500} {...num('checks_per_asset_day')} /></div>
              <div className="field" style={{ flex: '1 1 180px' }}><label htmlFor="cpu">Checks par utilisateur et par heure</label><input id="cpu" className="input" type="number" min={1} max={1000} {...num('checks_per_user_hour')} /></div>
            </div>
          ) : <Loading />}
          {form && (
            <label className="check" style={{ alignItems: 'flex-start', minHeight: 0 }}>
              <input type="checkbox" checked={form.allow_unsigned_plugins} onChange={(e) => setForm({ ...form, allow_unsigned_plugins: e.target.checked })} style={{ marginTop: 3 }} />
              <span><strong>Mode développeur</strong> : autoriser les plugins non signés.<span className="hint" style={{ display: 'block' }}>Réservé à l'écriture et au test de plugins. Activation, désactivation et chaque installation non signée sont journalisées.</span></span>
            </label>
          )}
          <ErrorBox error={err} />
          {msg && <div className="notice ok"><strong>{msg}</strong></div>}
          <div className="btns"><button className="btn primary" type="submit">Enregistrer</button></div>
        </form>
      </div>
      <section className="card col-1">
        <h2>Auto-test du récepteur</h2>
        {rcv && (
          <>
            <div className="kv"><span>DNS {rcv.dns_addr}</span><span style={{ color: rcv.dns_up ? 'var(--green)' : 'var(--red)' }}>{rcv.dns_up ? 'En écoute' : 'Arrêté'}</span></div>
            <div className="kv"><span>HTTP {rcv.http_addr}</span><span style={{ color: rcv.http_up ? 'var(--green)' : 'var(--red)' }}>{rcv.http_up ? 'En écoute' : 'Arrêté'}</span></div>
          </>
        )}
        {test && test.steps.map((s) => (
          <div key={s.name} className="stack" style={{ gap: 2 }}>
            <div className="kv"><span>{s.name}</span><span style={{ color: s.ok ? 'var(--green)' : 'var(--red)' }}>{s.ok ? 'OK' : 'Échec'}</span></div>
            <span className="small dim">{s.detail}</span>
          </div>
        ))}
        <button className="btn" type="button" disabled={testing} onClick={async () => {
          setTesting(true)
          try { setTest(await post('/api/receiver/selftest')) } catch (e) { setErr((e as Error).message) } finally { setTesting(false) }
        }}>{testing ? 'Test en cours (jusqu’à 20 s)…' : 'Lancer l’auto-test'}</button>
        <p className="hint">Vérifie l'écoute locale, puis la délégation publique en interrogeant les résolveurs configurés : un échec de ces derniers signale une délégation NS absente ou un port 53 fermé.</p>
      </section>
    </div>
  )
}
