import { Fragment, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { post } from '../api'
import { can, useAuth } from '../auth'
import { CallbackPill, ErrorBox, Loading, Tabs, useLoad } from '../components/ui'
import { dateTime } from '../format'
import type { AuditEntry, Asset, Callback, Campaign, ReportRow } from '../types'

// ---------------------------------------------------------------------------------------------

export function Callbacks() {
  const [f, setF] = useState<'all' | 'correlated' | 'rejected' | 'alerts' | 'selftest'>('all')
  const { data, error } = useLoad<Callback[]>(`/api/callbacks${f === 'all' ? '' : `?status=${f}`}`, 5000)
  const [open, setOpen] = useState<number | null>(null)
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Callbacks canari</h1>
          <p className="lead">Tout ce que reçoit le récepteur, y compris les requêtes rejetées (jeton inconnu, expiré ou rejoué). Les requêtes rejetées ne produisent jamais de verdict.</p>
        </div>
      </header>
      <Tabs label="Filtrer" value={f} onChange={setF} items={[['all', 'Tous'], ['correlated', 'Corrélés'], ['rejected', 'Rejetés'], ['alerts', 'Alertes'], ['selftest', 'Auto-tests']]} />
      <ErrorBox error={error} />
      {!data ? !error && <Loading /> : (
        <div className="card flush table-wrap">
          <table className="t" style={{ minWidth: 980 }}>
            <thead><tr><th>Reçu</th><th>Proto</th><th>Nom interrogé</th><th>Source</th><th>Corrélation</th><th>Statut</th></tr></thead>
            <tbody>
              {data.length === 0 && <tr><td colSpan={6} className="muted" style={{ textAlign: 'center', padding: 28 }}>Aucun callback.</td></tr>}
              {data.map((c) => (
                <Fragment key={c.id}>
                  <tr className="link" onClick={() => setOpen(open === c.id ? null : c.id)} aria-expanded={open === c.id}>
                    <td className="muted" style={{ whiteSpace: 'nowrap' }}>{dateTime(c.received_at)}</td>
                    <td>{c.proto.toUpperCase()} {c.qtype}</td>
                    <td className="mono break">{c.qname}</td>
                    <td className="mono">{c.source_ip}
                      {c.source_matches !== null && c.check_id && <div className="sub" style={{ color: c.source_matches ? 'var(--green)' : 'var(--warn)', fontFamily: 'Inter, sans-serif' }}>{c.source_matches ? '= IP de l’asset' : '≠ IP de l’asset (résolveur)'}</div>}
                    </td>
                    <td className="muted">{c.check_id ? <Link to={`/checks/${c.check_id}`} onClick={(e) => e.stopPropagation()}>{c.asset_host} · {c.checker}</Link> : c.status === 'honeytoken' ? <Link to="/assets" onClick={(e) => e.stopPropagation()} style={{ color: 'var(--red)' }}>canari fichier de {c.asset_host} lu hors check</Link> : c.status === 'unknown' ? 'jeton inconnu ou signature invalide' : c.status === 'selftest' ? 'auto-test du récepteur' : '—'}</td>
                    <td><CallbackPill s={c.status} /></td>
                  </tr>
                  {open === c.id && (
                    <tr><td colSpan={6}><pre className="code">{c.raw || '(vide)'}</pre></td></tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="hint">Un pic de jetons inconnus peut signaler un scan de la zone canari. Leur enregistrement est limité à 120 par minute.</p>
    </>
  )
}

// ---------------------------------------------------------------------------------------------

export function Reports() {
  const { me } = useAuth()
  const [params] = useSearchParams()
  const { data, error, reload } = useLoad<ReportRow[]>('/api/reports')
  const { data: camps } = useLoad<Campaign[]>('/api/campaigns')
  const { data: assets } = useLoad<Asset[]>('/api/assets')
  const [scope, setScope] = useState(params.get('campagne') ? `c:${params.get('campagne')}` : 'all')
  const [days, setDays] = useState(30)
  const [fmt, setFmt] = useState<'pdf' | 'html' | 'json'>('pdf')
  const [raw, setRaw] = useState(true)
  const [inc, setInc] = useState(false)
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function generate() {
    setBusy(true)
    setErr('')
    try {
      const body: Record<string, unknown> = { format: fmt, include_raw: raw, include_inconclusive: inc, days }
      if (scope.startsWith('c:')) body.campaign_id = Number(scope.slice(2))
      if (scope.startsWith('a:')) body.asset_id = Number(scope.slice(2))
      await post('/api/reports', body)
      await reload()
    } catch (e) {
      setErr((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Rapports</h1>
          <p className="lead">Chaque rapport embarque les preuves (canari, horodatages, source, requête brute) et son empreinte SHA-256 est conservée par l'instance.</p>
        </div>
      </header>
      <div className="row">
        {can(me.user.role, 'analyst') && (
          <section className="card col-1">
            <h2>Nouveau rapport</h2>
            <div className="field">
              <label htmlFor="scope">Périmètre</label>
              <select id="scope" className="input" value={scope} onChange={(e) => setScope(e.target.value)}>
                <option value="all">Tous les assets</option>
                <optgroup label="Campagnes">
                  {camps?.slice(0, 50).map((c) => <option key={c.id} value={`c:${c.id}`}>Campagne #{c.id} · {c.asset_host}</option>)}
                </optgroup>
                <optgroup label="Assets">
                  {assets?.map((a) => <option key={a.id} value={`a:${a.id}`}>{a.host}</option>)}
                </optgroup>
              </select>
            </div>
            {!scope.startsWith('c:') && (
              <div className="field">
                <label htmlFor="days">Période (jours)</label>
                <input id="days" className="input" type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} />
              </div>
            )}
            <fieldset style={{ border: 0, margin: 0, padding: 0 }}>
              <legend className="label" style={{ paddingBottom: 10 }}>Format</legend>
              <Tabs label="Format" value={fmt} onChange={setFmt} items={[['pdf', 'PDF'], ['html', 'HTML'], ['json', 'JSON']]} />
            </fieldset>
            <label className="check"><input type="checkbox" checked={raw} onChange={(e) => setRaw(e.target.checked)} />Inclure les requêtes brutes reçues</label>
            <label className="check"><input type="checkbox" checked={inc} onChange={(e) => setInc(e.target.checked)} />Inclure les checks non concluants et en erreur</label>
            <ErrorBox error={err} />
            <button className="btn primary" type="button" disabled={busy} onClick={() => void generate()}>{busy ? 'Génération…' : 'Générer'}</button>
          </section>
        )}
        <section className="card col-2">
          <h2>Rapports générés</h2>
          <ErrorBox error={error} />
          {!data ? !error && <Loading /> : data.length === 0 ? <p className="muted">Aucun rapport.</p> : (
            <div className="table-wrap">
              <table className="t" style={{ minWidth: 620 }}>
                <thead><tr><th>Rapport</th><th>Contenu</th><th>Créé</th><th>Fichier</th></tr></thead>
                <tbody>
                  {data.map((r) => (
                    <tr key={r.id}>
                      <td><div style={{ fontWeight: 500 }}>{r.title}</div><div className="sub mono" title={r.sha256}>sha256 {r.sha256.slice(0, 16)}…</div></td>
                      <td className="muted">{r.summary}</td>
                      <td className="muted" style={{ whiteSpace: 'nowrap' }}>{dateTime(r.created_at)}<div className="sub">{r.created_by}</div></td>
                      <td>
                        <div className="btns" style={{ gap: 6 }}>
                          <a className="btn small" href={`/api/reports/${r.id}/download`} target="_blank" rel="noreferrer">Ouvrir</a>
                          <a className="btn small" href={`/api/reports/${r.id}/download?download=1`}>{r.format.toUpperCase()}</a>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </>
  )
}

// ---------------------------------------------------------------------------------------------

const actionTone: Record<string, string> = {
  'Check lancé': 'yellow', Refus: 'red', 'Connexion refusée': 'red', 'Preuve de propriété': 'green', 'Asset déclaré': 'green',
  'Liste blanche': 'accent', 'Rôle modifié': 'accent', 'Utilisateur créé': 'accent', 'Réglages modifiés': 'accent',
}

export function Audit() {
  const [user, setUser] = useState('')
  const [action, setAction] = useState('')
  const [days, setDays] = useState('7')
  const q = new URLSearchParams({ ...(user && { user }), ...(action && { action }), ...(days && { days }) }).toString()
  const { data, error } = useLoad<{ entries: AuditEntry[]; actors: string[]; actions: string[] }>(`/api/audit?${q}`)
  const { data: chain } = useLoad<{ ok: boolean; count: number; broken_at?: number; reason?: string }>('/api/audit/verify')
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Journal d'audit</h1>
          <p className="lead">En ajout seul, chaîné par empreinte : une ligne modifiée ou supprimée casse la chaîne.</p>
        </div>
        <div className="btns">
          {chain && (chain.ok
            ? <span className="pill green">Chaîne intègre · {chain.count} entrées</span>
            : <span className="pill red">Chaîne rompue à l'entrée #{chain.broken_at} : {chain.reason}</span>)}
          <a className="btn" href={`/api/audit/export.jsonl?${q}`}>Exporter (JSONL)</a>
        </div>
      </header>
      <div className="btns" style={{ alignItems: 'flex-end' }}>
        <div className="field"><label htmlFor="fu">Utilisateur</label>
          <select id="fu" className="input" value={user} onChange={(e) => setUser(e.target.value)} style={{ minWidth: 200 }}>
            <option value="">Tous</option>{data?.actors.map((a) => <option key={a}>{a}</option>)}
          </select></div>
        <div className="field"><label htmlFor="fa">Action</label>
          <select id="fa" className="input" value={action} onChange={(e) => setAction(e.target.value)} style={{ minWidth: 200 }}>
            <option value="">Toutes</option>{data?.actions.map((a) => <option key={a}>{a}</option>)}
          </select></div>
        <div className="field"><label htmlFor="fd">Période</label>
          <select id="fd" className="input" value={days} onChange={(e) => setDays(e.target.value)} style={{ minWidth: 160 }}>
            <option value="1">24 heures</option><option value="7">7 jours</option><option value="30">30 jours</option><option value="">Tout</option>
          </select></div>
      </div>
      <ErrorBox error={error} />
      {!data ? !error && <Loading /> : (
        <div className="card flush table-wrap">
          <table className="t" style={{ minWidth: 940 }}>
            <thead><tr><th>Horodatage</th><th>Utilisateur</th><th>Action</th><th>Détail</th><th>IP</th></tr></thead>
            <tbody>
              {data.entries.length === 0 && <tr><td colSpan={5} className="muted" style={{ textAlign: 'center', padding: 28 }}>Aucune entrée.</td></tr>}
              {data.entries.map((e) => (
                <tr key={e.id}>
                  <td className="muted" style={{ whiteSpace: 'nowrap' }}>{dateTime(e.at)}</td>
                  <td>{e.actor}</td>
                  <td><span className={`pill ${actionTone[e.action] ?? 'gray'}`}>{e.action}</span></td>
                  <td style={{ color: 'var(--text-2)' }}>{e.detail}</td>
                  <td className="mono muted">{e.ip || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}
