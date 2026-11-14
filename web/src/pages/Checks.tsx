import { Fragment, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import { del, post, put } from '../api'
import { can, useAuth } from '../auth'
import { CallbackPill, ErrorBox, Loading, ModePill, VerdictPill, useLoad } from '../components/ui'
import { ago, dateTime, daysLeft, isPending, statusLabel, verdictLabel } from '../format'
import type { Asset, Campaign, Check, CheckFull, CheckerInfo, FileCanary, Settings } from '../types'

// ---------------------------------------------------------------------------------------------

export function Launch() {
  const [params] = useSearchParams()
  const nav = useNavigate()
  const { data: assets } = useLoad<Asset[]>('/api/assets')
  const { data: checkers } = useLoad<CheckerInfo[]>('/api/checkers')
  const [assetID, setAssetID] = useState<number>(Number(params.get('asset')) || 0)
  const [target, setTarget] = useState('')
  const [picked, setPicked] = useState<Set<string>>(new Set(params.get('checker') ? [params.get('checker')!] : []))
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [repeat, setRepeat] = useState(0)
  const asset = assets?.find((a) => a.id === assetID)
  const { data: fileCanary } = useLoad<FileCanary | null>(assetID ? `/api/assets/${assetID}/canary` : null)
  const needsFile = (c: CheckerInfo) => c.requires_file_canary && !fileCanary

  useEffect(() => {
    if (!assetID && assets) {
      const first = assets.find((a) => a.owned)
      if (first) setAssetID(first.id)
    }
  }, [assets, assetID])
  useEffect(() => {
    if (asset) setTarget(asset.default_url)
  }, [asset])
  // Suggestion selon les tags de l'asset.
  const suggested = useMemo(() => {
    if (!asset || !checkers) return new Set<string>()
    return new Set(checkers.filter((c) => c.tags.some((t) => asset.tags.includes(t))).map((c) => c.id))
  }, [asset, checkers])
  useEffect(() => {
    if (suggested.size && picked.size === 0) setPicked(new Set(suggested))
  }, [suggested]) // eslint-disable-line react-hooks/exhaustive-deps
  // Un checker qui exige un canari fichier absent est retiré de la sélection.
  useEffect(() => {
    if (!checkers) return
    const blocked = checkers.filter(needsFile).map((c) => c.id)
    if (blocked.some((id) => picked.has(id))) setPicked(new Set([...picked].filter((id) => !blocked.includes(id))))
  }, [fileCanary, checkers, assetID]) // eslint-disable-line react-hooks/exhaustive-deps

  async function launch() {
    setBusy(true)
    setError('')
    try {
      const r = await post<{ id: number }>('/api/campaigns', { asset_id: assetID, target_url: target, checkers: [...picked] })
      if (repeat > 0) {
        await post('/api/schedules', { asset_id: assetID, target_url: target, checkers: [...picked], every_days: repeat, first_run_in_days: repeat })
      }
      nav(`/campagnes/${r.id}`)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  const canaries = checkers?.filter((c) => picked.has(c.id) && c.mode === 'canary').length ?? 0
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Lancer un check</h1>
          <p className="lead">Un canari distinct est émis pour chaque couple asset × checker. La propriété de l'asset est revalidée juste avant l'envoi.</p>
        </div>
      </header>
      <div className="row">
        <div className="col-2 stack">
          <section className="card">
            <h2>1. Asset cible</h2>
            {!assets && <Loading />}
            {assets?.length === 0 && <p className="muted">Aucun asset. <Link to="/assets/nouveau">Déclarez-en un</Link> et prouvez sa propriété.</p>}
            {assets?.map((a) => {
              const on = a.id === assetID
              const d = daysLeft(a.proof_valid_until)
              return (
                <button key={a.id} type="button" disabled={!a.owned} onClick={() => a.owned && setAssetID(a.id)} aria-pressed={on}
                  className={`choice ${on ? 'on' : ''}`} style={{ flexDirection: 'row', alignItems: 'center', minHeight: 48, gap: 12, flex: 'none' }}>
                  <span style={{ width: 16, height: 16, borderRadius: 8, border: `2px solid ${on ? 'var(--accent)' : '#4a5260'}`, background: on ? 'var(--accent-strong)' : 'transparent', flex: 'none' }} />
                  <span className="mono" style={{ flex: '1 1 auto' }}>{a.host}</span>
                  <span className="small" style={{ color: a.owned ? 'var(--muted)' : 'var(--red)' }}>{a.owned ? `Prouvée · ${d} j restants` : 'Propriété non prouvée'}</span>
                </button>
              )
            })}
            {asset && (
              <div className="field">
                <label htmlFor="target">URL cible {asset.kind === 'cidr' ? '(une adresse de la plage)' : ''}</label>
                <input id="target" className="input mono" value={target} placeholder={asset.kind === 'cidr' ? 'http://10.20.0.12:8080/' : ''} onChange={(e) => setTarget(e.target.value)} />
                <p className="hint">Doit viser {asset.kind === 'cidr' ? `une adresse de ${asset.host}` : asset.host}. Le chemin et le port sont libres : visez la page qui traite les entrées (formulaire, API…).</p>
              </div>
            )}
          </section>
          <section className="card">
            <h2>2. Checkers</h2>
            {checkers?.map((c) => (
              <label key={c.id} className="check" style={{ padding: '0 12px', borderRadius: 8, background: 'var(--field)', border: '1px solid var(--line)', opacity: needsFile(c) ? 0.55 : 1 }}>
                <input type="checkbox" disabled={needsFile(c)} checked={picked.has(c.id)} onChange={(e) => {
                  const n = new Set(picked)
                  if (e.target.checked) n.add(c.id)
                  else n.delete(c.id)
                  setPicked(n)
                }} />
                <span style={{ flex: '1 1 auto' }}>{c.name} <span className="small dim">· {c.cves.join(', ')}</span></span>
                {needsFile(c) && asset && <Link to={`/assets/${asset.id}`} className="small">canari fichier requis</Link>}
                {c.source === 'plugin' && <span className="small dim">plugin</span>}
                {suggested.has(c.id) && !needsFile(c) && <span className="small" style={{ color: 'var(--accent)' }}>suggéré</span>}
                <ModePill mode={c.mode} />
              </label>
            ))}
            <p className="hint">Suggestions d'après les tags de l'asset. Le contenu des payloads n'est pas modifiable.</p>
          </section>
        </div>
        <aside className="card col-1">
          <h2>Avant l'envoi</h2>
          <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.8, fontSize: 13.5, color: 'var(--text-2)' }}>
            <li>Propriété revalidée au lancement</li>
            <li>Adresses contactées limitées à l'asset</li>
            <li>Limites de débit par asset et par utilisateur</li>
            <li>Action inscrite au journal d'audit</li>
          </ul>
          <SettingsSummary canaries={canaries} />
          <div className="field">
            <label htmlFor="repeat">Répétition</label>
            <select id="repeat" className="input" value={repeat} onChange={(e) => setRepeat(Number(e.target.value))}>
              <option value={0}>Une seule fois</option>
              <option value={7}>Maintenant, puis chaque semaine</option>
              <option value={30}>Maintenant, puis chaque mois</option>
              <option value={90}>Maintenant, puis chaque trimestre</option>
            </select>
            <p className="hint">Chaque exécution programmée revalide la propriété et respecte les limites, comme un lancement manuel.</p>
          </div>
          <ErrorBox error={error} />
          <button className="btn primary" type="button" disabled={busy || !asset?.owned || picked.size === 0} onClick={() => void launch()} style={{ minHeight: 46 }}>
            {busy ? 'Revalidation de la propriété…' : `Lancer ${picked.size} check${picked.size > 1 ? 's' : ''}`}
          </button>
        </aside>
      </div>
    </>
  )
}

function SettingsSummary({ canaries }: { canaries: number }) {
  const { me } = useAuth()
  const { data } = useLoad<Settings>(can(me.user.role, 'admin') ? '/api/settings' : null)
  return (
    <div style={{ borderTop: '1px solid var(--row)', paddingTop: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div className="kv"><span>Canaris émis</span><span>{canaries} (usage unique)</span></div>
      {data && <div className="kv"><span>Durée de vie</span><span>{data.canary_ttl_minutes} min</span></div>}
      {data && <div className="kv"><span>Attente du callback</span><span>{data.wait_seconds} s</span></div>}
    </div>
  )
}

interface ScheduleRow { id: number; asset_host: string; checkers: string[]; every_days: number; next_run_at: string; enabled: boolean; created_by: string; last_campaign_id: number | null; last_error: string }

// ---------------------------------------------------------------------------------------------

export function Campaigns() {
  const { me } = useAuth()
  const nav = useNavigate()
  const { data, error } = useLoad<Campaign[]>('/api/campaigns', 5000)
  const { data: schedules, reload: reloadSchedules } = useLoad<ScheduleRow[]>('/api/schedules')
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Checks</h1>
          <p className="lead">Historique des campagnes. Une campagne regroupe les checks lancés ensemble sur un asset.</p>
        </div>
        {can(me.user.role, 'analyst') && <Link className="btn primary" to="/checks/nouveau">Lancer un check</Link>}
      </header>
      <ErrorBox error={error} />
      {schedules && schedules.length > 0 && (
        <section className="card">
          <h2>Checks programmés</h2>
          <div className="table-wrap">
            <table className="t" style={{ minWidth: 760 }}>
              <thead><tr><th>Asset</th><th>Checkers</th><th>Fréquence</th><th>Prochaine exécution</th><th>Dernière</th><th></th></tr></thead>
              <tbody>{schedules.map((p) => (
                <tr key={p.id} style={{ opacity: p.enabled ? 1 : 0.55 }}>
                  <td className="mono">{p.asset_host}<div className="sub">{p.created_by}</div></td>
                  <td className="small">{p.checkers.join(', ')}</td>
                  <td>tous les {p.every_days} j</td>
                  <td className="muted">{p.enabled ? dateTime(p.next_run_at) : 'suspendu'}</td>
                  <td className="small">{p.last_error ? <span style={{ color: 'var(--red)' }}>{p.last_error}</span> : p.last_campaign_id ? <Link to={`/campagnes/${p.last_campaign_id}`}>campagne #{p.last_campaign_id}</Link> : '—'}</td>
                  <td>{can(me.user.role, 'analyst') && <div className="btns" style={{ gap: 6 }}>
                    <button type="button" className="btn small" onClick={async () => { await put(`/api/schedules/${p.id}`, { enabled: !p.enabled }); await reloadSchedules() }}>{p.enabled ? 'Suspendre' : 'Réactiver'}</button>
                    <button type="button" className="btn small danger" onClick={async () => { if (window.confirm('Supprimer cette programmation ?')) { await del(`/api/schedules/${p.id}`); await reloadSchedules() } }}>Supprimer</button>
                  </div>}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </section>
      )}
      {!data ? !error && <Loading /> : (
        <div className="card flush table-wrap">
          <table className="t" style={{ minWidth: 760 }}>
            <thead><tr><th>Campagne</th><th>Asset</th><th>Résultat</th><th>Lancée par</th><th>Quand</th></tr></thead>
            <tbody>
              {data.length === 0 && <tr><td colSpan={5} className="muted" style={{ textAlign: 'center', padding: 28 }}>Aucune campagne.</td></tr>}
              {data.map((c) => (
                <tr key={c.id} className="link" onClick={() => nav(`/campagnes/${c.id}`)}>
                  <td><Link to={`/campagnes/${c.id}`}>#{c.id}</Link></td>
                  <td className="mono">{c.asset_host}<div className="sub break">{c.target_url}</div></td>
                  <td>
                    {c.pending > 0 ? <span className="pill yellow">{c.pending} en cours</span> : c.cancelled ? <span className="pill gray">Annulée</span> : null}{' '}
                    {c.proved > 0 && <span className="pill red">{c.proved} prouvé(s)</span>}{' '}
                    {c.probable > 0 && <span className="pill orange">{c.probable} probable(s)</span>}{' '}
                    {c.pending === 0 && c.proved === 0 && c.probable === 0 && !c.cancelled && <span className="pill blue">{c.total} sans preuve</span>}
                  </td>
                  <td className="muted">{c.created_by}</td>
                  <td className="muted">{ago(c.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  )
}

// ---------------------------------------------------------------------------------------------

function stepsOf(c: Check) {
  const d = c.detail
  type S = { label: string; detail: string; state: 'done' | 'hit' | 'cur' | 'todo' }
  const s: S[] = []
  const started = c.status !== 'queued'
  s.push({ label: 'Propriété revalidée, cible résolue', detail: d.resolved_ips?.join(', ') ?? '', state: started ? 'done' : 'cur' })
  if (c.mode === 'canary') {
    s.push({ label: 'Canari émis', detail: d.canary_expires_at ? `usage unique · expire à ${dateTime(d.canary_expires_at)}` : '', state: d.canary ? 'done' : started ? 'cur' : 'todo' })
    s.push({ label: 'Payload envoyé', detail: d.points ? `${d.points.length} point(s) d'injection` : '', state: c.sent_at ? 'done' : d.canary ? 'cur' : 'todo' })
    if (d.callback) {
      s.push({ label: `Callback ${d.callback.Proto.toUpperCase()} reçu après ${((d.delta_ms ?? 0) / 1000).toFixed(1)} s`, detail: `source ${d.callback.Source}${d.callback.SourceMatches ? ' = IP de l’asset' : ''}`, state: 'hit' })
    } else {
      s.push({ label: 'En attente du callback', detail: 'DNS et HTTP surveillés', state: c.status === 'waiting' ? 'cur' : c.sent_at ? 'done' : 'todo' })
    }
  } else {
    s.push({ label: 'Lecture de l’empreinte', detail: 'aucune charge envoyée', state: c.status === 'done' ? 'done' : started ? 'cur' : 'todo' })
  }
  s.push({ label: c.verdict ? `Verdict : ${verdictLabel[c.verdict].toLowerCase()}` : c.status === 'cancelled' ? 'Annulé' : 'Verdict', detail: c.summary, state: c.verdict ? (c.verdict === 'proved' ? 'hit' : 'done') : 'todo' })
  return s
}

function Progress({ c }: { c: Check }) {
  const [now, setNow] = useState(Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [])
  if (c.status !== 'waiting' || !c.sent_at || !c.detail.wait_seconds) return null
  const el = Math.min(c.detail.wait_seconds, Math.max(0, Math.round((now - new Date(c.sent_at).getTime()) / 1000)))
  return (
    <div className="stack" style={{ gap: 6 }}>
      <div className="progress" role="progressbar" aria-label="Attente du callback" aria-valuenow={el} aria-valuemin={0} aria-valuemax={c.detail.wait_seconds}>
        <div style={{ width: `${(100 * el) / c.detail.wait_seconds}%` }} />
      </div>
      <span className="small muted">{el} s sur {c.detail.wait_seconds} s. Sans callback, verdict « non concluant ».</span>
    </div>
  )
}

export function CampaignView() {
  const { id } = useParams()
  const { me } = useAuth()
  const { data, error, reload } = useLoad<Campaign>(`/api/campaigns/${id}`, 1500)
  const [err, setErr] = useState('')
  if (!data) return error ? <ErrorBox error={error} /> : <Loading />
  const live = data.checks?.some(isPending)
  return (
    <>
      <header className="page-head">
        <div>
          <span className="crumbs"><Link to="/checks">Checks</Link> / Campagne #{data.id} · lancée par {data.created_by} le {dateTime(data.created_at)}</span>
          <h1 className="mono" style={{ fontFamily: 'var(--mono)', fontSize: 26 }}>{data.asset_host}</h1>
          <span className="mono small muted break">{data.target_url}</span>
        </div>
        <div className="btns">
          {live && can(me.user.role, 'analyst') && (
            <button className="btn" type="button" onClick={async () => {
              try { await post(`/api/campaigns/${data.id}/cancel`); void reload() } catch (e) { setErr((e as Error).message) }
            }}>Annuler la campagne</button>
          )}
          {!live && can(me.user.role, 'analyst') && <Link className="btn" to={`/rapports?campagne=${data.id}`}>Générer le rapport</Link>}
        </div>
      </header>
      <ErrorBox error={err} />
      <div className="row">
        {data.checks?.map((c) => (
          <section key={c.id} className="card" style={{ flex: '1 1 420px' }}>
            <div className="card-head" style={{ alignItems: 'flex-start' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <h2 style={{ fontFamily: 'var(--display)', fontSize: 19 }}>{c.checker_name}</h2>
                <span className="mono" style={{ color: '#aeb7c4' }}>{c.cves.join(' · ')}</span>
              </div>
              {c.verdict ? <VerdictPill v={c.verdict} /> : <span className="pill yellow">{statusLabel[c.status]}</span>}
            </div>
            {c.detail.canary && (
              <div className="code" style={{ padding: '10px 14px' }}>
                <div className="dim" style={{ fontFamily: 'Inter, sans-serif', fontSize: 11.5, letterSpacing: 0.8, textTransform: 'uppercase' }}>Canari de ce check</div>
                <span style={{ color: 'var(--accent)' }}>{c.detail.canary}</span>
              </div>
            )}
            <ol className="steps">
              {stepsOf(c).map((s, i) => (
                <li key={i}>
                  <span className={`mark ${s.state}`} aria-hidden="true">{s.state === 'done' ? '✓' : s.state === 'hit' ? '!' : s.state === 'cur' ? '…' : ''}</span>
                  <span style={{ display: 'flex', flexDirection: 'column', gap: 2, fontSize: 13.5 }}>
                    <span style={{ color: s.state === 'hit' ? 'var(--red)' : s.state === 'cur' ? 'var(--accent)' : s.state === 'todo' ? 'var(--dim)' : 'var(--text)' }}>{s.label}</span>
                    {s.detail && <span className="small dim">{s.detail}</span>}
                  </span>
                </li>
              ))}
            </ol>
            <Progress c={c} />
            {!isPending(c) && <Link className="btn primary" to={`/checks/${c.id}`}>Voir le verdict et la preuve</Link>}
          </section>
        ))}
      </div>
      <section className="card">
        <h2>Événements du récepteur{live ? ' (en direct)' : ''}</h2>
        {(data.events ?? []).length === 0 ? <p className="muted small" style={{ margin: 0 }}>Aucun callback reçu pour cette campagne.</p> : (
          <div className="log" role="log">
            {[...(data.events ?? [])].reverse().map((e) => (
              <div key={e.id}>
                <span className="dim">{dateTime(e.received_at)}</span>  <span style={{ color: e.status === 'correlated' ? 'var(--red)' : 'var(--muted)' }}>{e.status === 'correlated' ? 'CALLBACK' : e.status.toUpperCase()}</span>  {e.proto.toUpperCase()} {e.qtype}  {e.qname}  depuis {e.source_ip}
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  )
}

// ---------------------------------------------------------------------------------------------

export function CheckResult() {
  const { id } = useParams()
  const { me } = useAuth()
  const { data: c, error } = useLoad<CheckFull>(`/api/checks/${id}`, 3000)
  if (!c) return error ? <ErrorBox error={error} /> : <Loading />
  const d = c.detail
  const proved = c.verdict === 'proved'
  const hit = d.callback
  const point = d.points?.find((p) => p.id === hit?.Point)
  return (
    <>
      <nav aria-label="Fil d'Ariane" className="crumbs"><Link to={`/campagnes/${c.campaign_id}`}>Campagne #{c.campaign_id}</Link> / {c.checker_name}</nav>
      <section className={`card ${proved ? 'hero-proved' : ''}`} style={{ flexDirection: 'row', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 24, padding: 26 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, minWidth: 0 }}>
          <span>{c.verdict ? <VerdictPill v={c.verdict} /> : <span className="pill yellow">{statusLabel[c.status]}</span>}</span>
          <h1>{c.asset_host} · {c.checker_name}</h1>
          <p className="lead" style={{ color: 'var(--text-2)' }}>{c.cves.join(' · ')} · {c.summary || 'Check en cours.'}</p>
        </div>
        {can(me.user.role, 'analyst') && (
          <div className="btns">
            <Link className="btn primary" to={`/rapports?campagne=${c.campaign_id}`}>Générer le rapport</Link>
            <Link className="btn" to={`/checks/nouveau?asset=${c.asset_id}&checker=${c.checker}`}>Relancer après correctif</Link>
          </div>
        )}
      </section>
      <div className="row">
        <section className="card col-2">
          <h2>{c.mode === 'canary' ? 'Preuve du callback' : 'Empreinte relevée'}</h2>
          <dl className="grid">
            <dt>URL cible</dt><dd className="mono">{c.target_url}</dd>
            <dt>Adresses contactées</dt><dd className="mono">{d.resolved_ips?.join(', ') || '—'}</dd>
            {d.canary && (<><dt>Canari</dt><dd className="mono" style={{ color: 'var(--accent)' }}>{d.canary}</dd></>)}
            {d.canary && (<><dt>Lié à</dt><dd>asset {c.asset_host} · check #{c.id} · campagne #{c.campaign_id} (signature HMAC)</dd></>)}
            {hit && (<>
              <dt>Type de requête</dt><dd>{hit.Proto.toUpperCase()} {hit.QType}</dd>
              <dt>Source</dt><dd><span className="mono">{hit.Source}</span> <span style={{ color: hit.SourceMatches ? 'var(--green)' : 'var(--warn)' }}>· {hit.SourceMatches ? 'identique à une IP de l’asset' : 'différente des IP de l’asset (résolveur DNS ou sortie NAT : normal)'}</span></dd>
              <dt>Point d'injection</dt><dd>{point ? `${point.location} (${point.id})` : hit.Point || '—'}</dd>
            </>)}
            <dt>Envoi</dt><dd>{dateTime(c.sent_at ?? c.started_at)}</dd>
            {hit && (<><dt>Réception</dt><dd>{dateTime(hit.At)} (Δ {((d.delta_ms ?? 0) / 1000).toFixed(1)} s)</dd></>)}
            <dt>Verdict rendu</dt><dd>{dateTime(c.finished_at)}</dd>
            {d.evidence && Object.entries(d.evidence).map(([k, v]) => (<Fragment key={k}><dt>{k}</dt><dd className="mono">{v}</dd></Fragment>))}
            {d.error && (<><dt>Erreur</dt><dd style={{ color: 'var(--red)' }}>{d.error}</dd></>)}
          </dl>
          {c.callbacks.length > 0 && (
            <div className="stack" style={{ gap: 8 }}>
              <span className="label">Requêtes reçues ({c.callbacks.length})</span>
              {c.callbacks.map((cb) => (
                <div key={cb.id} className="stack" style={{ gap: 6 }}>
                  <div className="btns small"><CallbackPill s={cb.status} /><span className="muted">{dateTime(cb.received_at)} · {cb.proto.toUpperCase()} {cb.qtype} · {cb.point}</span></div>
                  <pre className="code">{cb.raw}</pre>
                </div>
              ))}
            </div>
          )}
          {d.points && d.points.length > 0 && (
            <details>
              <summary className="small" style={{ cursor: 'pointer', color: 'var(--accent)' }}>Points d'injection ({d.points.length})</summary>
              <table className="t"><tbody>{d.points.map((p) => (
                <tr key={p.id}><td className="mono">{p.id}</td><td>{p.location}</td><td className="muted">{p.error ? p.error : `HTTP ${p.status}`}</td></tr>
              ))}</tbody></table>
            </details>
          )}
        </section>
        <aside className="col-1 stack">
          <section className="card">
            <h2>Remédiation</h2>
            <ol style={{ margin: 0, paddingLeft: 18, lineHeight: 1.7, fontSize: 13.5, color: 'var(--text-2)' }}>{c.info.remediation?.map((r) => <li key={r}>{r}</li>)}</ol>
          </section>
          <section className="card">
            <h2>Ce qui a été envoyé</h2>
            <p className="muted small" style={{ margin: 0, lineHeight: 1.6 }}>{c.info.sent}</p>
            <ModePill mode={c.mode} />
          </section>
        </aside>
      </div>
    </>
  )
}
