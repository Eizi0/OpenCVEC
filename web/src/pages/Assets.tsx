import { useMemo, useState, type FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import { del, post, put } from '../api'
import { can, useAuth } from '../auth'
import { CopyButton, ErrorBox, Loading, Tabs, VerdictPill, useLoad } from '../components/ui'
import { dateTime, daysLeft, kindLabel, proofMethodLabel, statusLabel } from '../format'
import type { Asset } from '../types'

function ownership(a: Asset): { label: string; tone: string; sub: string } {
  const d = daysLeft(a.proof_valid_until)
  if (a.owned) {
    if (d !== null && d <= 7) return { label: 'À renouveler', tone: 'yellow', sub: `expire dans ${d} j` }
    return { label: a.proof_method === 'allowlist' ? 'Autorisée' : 'Prouvée', tone: 'green', sub: `expire dans ${d} j` }
  }
  if (a.proof_status === 'failed') return { label: 'Échec', tone: 'red', sub: a.proof_detail }
  if (a.proof_status === 'valid') return { label: 'Expirée', tone: 'yellow', sub: 'preuve à refaire' }
  return { label: 'En attente', tone: 'gray', sub: a.proof_detail || 'preuve non vérifiée' }
}

type Filter = 'all' | 'ok' | 'warn' | 'pend'

export function Assets() {
  const { me } = useAuth()
  const nav = useNavigate()
  const { data, error } = useLoad<Asset[]>('/api/assets')
  const [f, setF] = useState<Filter>('all')
  const [q, setQ] = useState('')
  const groups = useMemo(() => {
    const all = data ?? []
    const st = (a: Asset) => ownership(a).tone
    return {
      all,
      ok: all.filter((a) => st(a) === 'green'),
      warn: all.filter((a) => st(a) === 'yellow'),
      pend: all.filter((a) => st(a) === 'gray' || st(a) === 'red'),
    }
  }, [data])
  const rows = groups[f].filter((a) => !q || a.host.includes(q.toLowerCase()) || a.tags.some((t) => t.includes(q.toLowerCase())))
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Assets</h1>
          <p className="lead">Seuls les assets à propriété prouvée peuvent être vérifiés. La preuve expire au bout de 30 jours et est revalidée avant chaque campagne.</p>
        </div>
        {can(me.user.role, 'analyst') && <Link className="btn primary" to="/assets/nouveau">Ajouter un asset</Link>}
      </header>
      <ErrorBox error={error} />
      <div className="btns" style={{ justifyContent: 'space-between' }}>
        <Tabs label="Filtrer par statut" value={f} onChange={setF} items={[
          ['all', `Tous · ${groups.all.length}`], ['ok', `Prouvés · ${groups.ok.length}`],
          ['warn', `À renouveler · ${groups.warn.length}`], ['pend', `En attente / échec · ${groups.pend.length}`],
        ]} />
        <label style={{ flex: '0 1 320px' }}>
          <span className="sr-only">Rechercher un asset</span>
          <input className="input" placeholder="Rechercher un domaine, une IP, un tag…" value={q} onChange={(e) => setQ(e.target.value)} />
        </label>
      </div>
      {!data ? (
        !error && <Loading />
      ) : (
        <div className="card flush table-wrap">
          <table className="t" style={{ minWidth: 900 }}>
            <thead><tr><th>Asset</th><th>Type</th><th>Méthode de preuve</th><th>Propriété</th><th>Dernier verdict</th><th>Tags</th></tr></thead>
            <tbody>
              {rows.length === 0 && <tr><td colSpan={6} className="muted" style={{ textAlign: 'center', padding: 28 }}>Aucun asset.</td></tr>}
              {rows.map((a) => {
                const o = ownership(a)
                return (
                  <tr key={a.id} className="link" onClick={() => nav(`/assets/${a.id}`)}>
                    <td className="mono"><Link to={`/assets/${a.id}`} style={{ color: 'var(--text)' }}>{a.host}</Link></td>
                    <td className="muted">{kindLabel[a.kind]}</td>
                    <td className="muted">{proofMethodLabel[a.proof_method]}</td>
                    <td><span className={`pill ${o.tone}`}>{o.label}</span><div className="sub">{o.sub}</div></td>
                    <td><VerdictPill v={a.last_verdict} />{a.last_checker && <div className="sub">{a.last_checker}</div>}</td>
                    <td>{a.tags.map((t) => <span key={t} className="chip">{t}</span>)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="hint">Les plages privées (RFC 1918) et les adresses internes ne passent que par la liste blanche gérée en Administration ; chaque ajout est journalisé.</p>
    </>
  )
}

export function AssetNew() {
  const nav = useNavigate()
  const [host, setHost] = useState('')
  const [tags, setTags] = useState('')
  const [scheme, setScheme] = useState<'https' | 'http'>('https')
  const [port, setPort] = useState('')
  const [method, setMethod] = useState<Asset['proof_method']>('dns_txt')
  const [error, setError] = useState('')
  const looksIP = /^[0-9a-f:.]+(\/\d+)?$/i.test(host.trim()) && /[.:]/.test(host)
  const isCIDR = host.includes('/')

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError('')
    try {
      const a = await post<Asset>('/api/assets', {
        host, tags: tags.split(',').map((t) => t.trim()).filter(Boolean), scheme, port: port ? Number(port) : 0, proof_method: method,
      })
      nav(`/assets/${a.id}`)
    } catch (err) {
      setError((err as Error).message)
    }
  }
  const methods: [Asset['proof_method'], string, string, boolean][] = [
    ['dns_txt', 'Enregistrement DNS TXT', 'Recommandé pour un nom de domaine public', looksIP],
    ['well_known', 'Fichier /.well-known', 'Servi par le site lui-même', isCIDR],
    ['allowlist', 'Liste blanche', 'Réseau interne autorisé par un administrateur', false],
  ]
  return (
    <>
      <nav aria-label="Fil d'Ariane" className="crumbs"><Link to="/assets">Assets</Link> / Nouvel asset</nav>
      <h1>Ajouter un asset</h1>
      <div className="row">
        <form className="card col-2" onSubmit={submit} style={{ gap: 20 }}>
          <div className="row">
            <div className="field" style={{ flex: '2 1 260px' }}>
              <label htmlFor="host">Nom d'hôte, IP ou plage CIDR</label>
              <input id="host" className="input mono" required placeholder="app.exemple.fr" value={host} onChange={(e) => setHost(e.target.value)} />
            </div>
            <div className="field" style={{ flex: '1 1 180px' }}>
              <label htmlFor="tags">Tags (séparés par des virgules)</label>
              <input id="tags" className="input" placeholder="prod, java" value={tags} onChange={(e) => setTags(e.target.value)} />
            </div>
          </div>
          <div className="row">
            <div className="field" style={{ flex: '1 1 160px' }}>
              <label htmlFor="scheme">Schéma par défaut</label>
              <select id="scheme" className="input" value={scheme} onChange={(e) => setScheme(e.target.value as 'http' | 'https')}>
                <option value="https">https</option>
                <option value="http">http</option>
              </select>
            </div>
            <div className="field" style={{ flex: '1 1 160px' }}>
              <label htmlFor="port">Port (vide = par défaut)</label>
              <input id="port" className="input" inputMode="numeric" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))} />
            </div>
          </div>
          <fieldset style={{ border: 0, margin: 0, padding: 0, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <legend className="label" style={{ paddingBottom: 10 }}>Méthode de preuve</legend>
            <div className="btns">
              {methods.map(([id, title, sub, disabled]) => (
                <button key={id} type="button" disabled={disabled} className={`choice ${method === id ? 'on' : ''}`} aria-pressed={method === id} onClick={() => setMethod(id)}>
                  <span style={{ fontWeight: 600 }}>{title}</span>
                  <span className="small muted">{sub}</span>
                </button>
              ))}
            </div>
          </fieldset>
          <ErrorBox error={error} />
          <div className="btns">
            <button className="btn primary" type="submit">Déclarer l'asset</button>
            <Link to="/assets" className="small">Annuler</Link>
          </div>
        </form>
        <aside className="card col-1">
          <h2>Pourquoi cette étape ?</h2>
          <p className="muted" style={{ margin: 0, lineHeight: 1.6 }}>Sans preuve, OpenCVEC refuse tout check. Cela empêche d'utiliser la plateforme contre un système qui ne vous appartient pas.</p>
          <h3>Ce qui est contrôlé</h3>
          <ul className="muted" style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7, fontSize: 13 }}>
            <li>Le jeton est présent et identique.</li>
            <li>La majorité des résolveurs publics voient le même enregistrement.</li>
            <li>La preuve est revalidée avant chaque campagne.</li>
            <li>Les adresses contactées restent dans le périmètre de l'asset.</li>
          </ul>
        </aside>
      </div>
    </>
  )
}

export function AssetDetail() {
  const { id } = useParams()
  const { me } = useAuth()
  const nav = useNavigate()
  const { data: a, error, setData } = useLoad<Asset>(`/api/assets/${id}`)
  const { data: camps } = useLoad<{ id: number; asset_id: number; created_at: string; total: number; proved: number; probable: number; pending: number }[]>('/api/campaigns')
  const [busy, setBusy] = useState(false)
  const [msg, setMsg] = useState('')
  const [err, setErr] = useState('')
  const analyst = can(me.user.role, 'analyst')

  async function act(fn: () => Promise<Asset>) {
    setBusy(true)
    setErr('')
    setMsg('')
    try {
      const r = await fn()
      setData(r)
      return r
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  if (!a) return error ? <ErrorBox error={error} /> : <Loading />
  const o = ownership(a)
  const mine = (camps ?? []).filter((c) => c.asset_id === a.id).slice(0, 10)
  return (
    <>
      <nav aria-label="Fil d'Ariane" className="crumbs"><Link to="/assets">Assets</Link> / {a.host}</nav>
      <header className="page-head">
        <div>
          <h1 className="mono" style={{ fontFamily: 'var(--mono)', fontSize: 26 }}>{a.host}</h1>
          <p className="lead">{kindLabel[a.kind]} · preuve par {proofMethodLabel[a.proof_method]} · <span className={`pill ${o.tone}`}>{o.label}</span></p>
        </div>
        {analyst && (
          <div className="btns">
            {a.owned && <Link className="btn primary" to={`/checks/nouveau?asset=${a.id}`}>Lancer un check</Link>}
            <button className="btn danger" type="button" disabled={busy} onClick={async () => {
              if (!window.confirm(`Supprimer ${a.host} et son historique de checks ?`)) return
              try { await del(`/api/assets/${a.id}`); nav('/assets') } catch (e) { setErr((e as Error).message) }
            }}>Supprimer</button>
          </div>
        )}
      </header>
      <ErrorBox error={err} />
      <div className="row">
        <section className="card col-2" style={{ gap: 18 }}>
          <h2>Preuve de propriété</h2>
          {a.proof_method === 'dns_txt' && (
            <div className="stack" style={{ gap: 10 }}>
              <span className="label">Ajoutez cet enregistrement à votre zone DNS</span>
              <div className="code">
                <div><span className="dim">Nom    </span>{a.txt_name}  TXT</div>
                <div><span className="dim">Valeur </span><span style={{ color: 'var(--accent)' }}>{a.txt_value}</span></div>
              </div>
              <div className="btns"><CopyButton text={a.txt_value ?? ''} /><span className="hint">Jeton à publier avant le {dateTime(a.proof_token_expires)}.</span></div>
            </div>
          )}
          {a.proof_method === 'well_known' && (
            <div className="stack" style={{ gap: 10 }}>
              <span className="label">Publiez ce fichier sur le serveur</span>
              <div className="code">
                <div><span className="dim">URL     </span>{a.well_known_url}</div>
                <div><span className="dim">Contenu </span><span style={{ color: 'var(--accent)' }}>{a.proof_token}</span></div>
              </div>
              <div className="btns"><CopyButton text={a.proof_token} /><span className="hint">Jeton à publier avant le {dateTime(a.proof_token_expires)}.</span></div>
            </div>
          )}
          {a.proof_method === 'allowlist' && (
            <p className="muted" style={{ margin: 0 }}>
              L'asset doit appartenir entièrement à une plage autorisée par un administrateur (Administration › Liste blanche). La preuve dure au plus jusqu'à la date de revue de la plage.
            </p>
          )}
          {a.proof_checked_at && (
            <div className={`notice ${a.owned ? 'ok' : a.proof_status === 'failed' ? 'err' : 'warn'}`} role="status">
              <strong>{a.owned ? 'Propriété prouvée' : a.proof_status === 'failed' ? 'Preuve refusée' : 'Preuve à refaire'}</strong>
              <span>{a.proof_detail}</span>
              <span className="small muted">Vérifiée le {dateTime(a.proof_checked_at)}{a.proof_valid_until ? ` · valable jusqu'au ${dateTime(a.proof_valid_until)}` : ''}</span>
            </div>
          )}
          {msg && <div className="notice ok"><strong>{msg}</strong></div>}
          {analyst && (
            <div className="btns" style={{ borderTop: '1px solid var(--row)', paddingTop: 16 }}>
              <button className="btn primary" type="button" disabled={busy} onClick={() => void act(() => post<Asset>(`/api/assets/${a.id}/verify`))}>
                {busy ? 'Vérification…' : 'Vérifier maintenant'}
              </button>
              {a.proof_method !== 'allowlist' && (
                <button className="btn" type="button" disabled={busy} onClick={async () => {
                  if (!window.confirm('Générer un nouveau jeton ? La preuve actuelle sera invalidée.')) return
                  const r = await act(() => post<Asset>(`/api/assets/${a.id}/token`))
                  if (r) setMsg('Nouveau jeton généré : publiez-le puis vérifiez.')
                }}>Régénérer le jeton</button>
              )}
            </div>
          )}
        </section>
        <aside className="col-1 stack">
          <section className="card">
            <h2>Détails</h2>
            <div className="kv"><span>URL par défaut</span><span className="mono break">{a.default_url || '—'}</span></div>
            <div className="kv"><span>Adresses résolues</span><span className="mono break">{a.resolved_ips.join(', ') || '—'}</span></div>
            <div className="kv"><span>Déclaré le</span><span>{dateTime(a.created_at)}</span></div>
            <div>{a.tags.map((t) => <span key={t} className="chip">{t}</span>)}</div>
            {analyst && <AssetEdit a={a} onSaved={setData} />}
          </section>
          <section className="card">
            <h2>Campagnes récentes</h2>
            {mine.length === 0 && <p className="muted small" style={{ margin: 0 }}>Aucune campagne.</p>}
            {mine.map((c) => (
              <div key={c.id} className="kv">
                <Link to={`/campagnes/${c.id}`}>Campagne #{c.id}</Link>
                <span className="small muted">
                  {c.pending ? statusLabel.waiting : `${c.proved} prouvé(s) · ${c.probable} probable(s)`} · {dateTime(c.created_at)}
                </span>
              </div>
            ))}
          </section>
        </aside>
      </div>
    </>
  )
}

function AssetEdit({ a, onSaved }: { a: Asset; onSaved: (a: Asset) => void }) {
  const [open, setOpen] = useState(false)
  const [tags, setTags] = useState(a.tags.join(', '))
  const [scheme, setScheme] = useState(a.scheme)
  const [port, setPort] = useState(a.port ? String(a.port) : '')
  const [err, setErr] = useState('')
  if (!open) return <button type="button" className="btn small" onClick={() => setOpen(true)}>Modifier</button>
  return (
    <form className="stack" style={{ gap: 10 }} onSubmit={async (e) => {
      e.preventDefault()
      try {
        onSaved(await put<Asset>(`/api/assets/${a.id}`, { tags: tags.split(',').map((t) => t.trim()).filter(Boolean), scheme, port: port ? Number(port) : 0, proof_method: a.proof_method, host: a.host }))
        setOpen(false)
      } catch (e2) { setErr((e2 as Error).message) }
    }}>
      <div className="field"><label htmlFor="etags">Tags</label><input id="etags" className="input" value={tags} onChange={(e) => setTags(e.target.value)} /></div>
      <div className="row" style={{ gap: 10 }}>
        <div className="field" style={{ flex: '1 1 100px' }}><label htmlFor="esch">Schéma</label>
          <select id="esch" className="input" value={scheme} onChange={(e) => setScheme(e.target.value as 'http' | 'https')}><option>https</option><option>http</option></select></div>
        <div className="field" style={{ flex: '1 1 100px' }}><label htmlFor="eport">Port</label><input id="eport" className="input" value={port} onChange={(e) => setPort(e.target.value.replace(/\D/g, ''))} /></div>
      </div>
      <p className="hint">Changer le schéma ou le port impose de refaire la preuve.</p>
      <ErrorBox error={err} />
      <div className="btns"><button className="btn primary small" type="submit">Enregistrer</button><button className="btn small" type="button" onClick={() => setOpen(false)}>Annuler</button></div>
    </form>
  )
}
