import { Link, useNavigate } from 'react-router-dom'
import { can, useAuth } from '../auth'
import { ErrorBox, Loading, VerdictPill, useLoad } from '../components/ui'
import { ago, daysLeft } from '../format'
import type { Dashboard as D, Receiver } from '../types'

export function Dashboard() {
  const { me } = useAuth()
  const nav = useNavigate()
  const { data, error } = useLoad<D>('/api/dashboard', 10000)
  const { data: rcv } = useLoad<Receiver>('/api/receiver')
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Vue d'ensemble</h1>
          <p className="lead">Exposition prouvée de vos assets, sur les 30 derniers jours.</p>
        </div>
        {can(me.user.role, 'analyst') && <Link className="btn primary" to="/checks/nouveau">Lancer un check</Link>}
      </header>
      <ErrorBox error={error} />
      {!data ? (
        !error && <Loading />
      ) : (
        <>
          <section className="kpis" aria-label="Indicateurs">
            <div className="card kpi">
              <span className="muted small">Assets à propriété prouvée</span>
              <span className="v">{data.assets_owned}<small> / {data.assets_total}</small></span>
              <span className="small" style={{ color: data.assets_renew ? 'var(--accent)' : 'var(--muted)' }}>
                {data.assets_renew ? `${data.assets_renew} preuve(s) à renouveler sous 7 j` : 'aucune preuve à renouveler'}
              </span>
            </div>
            <div className="card kpi">
              <span className="muted small">Checks exécutés</span>
              <span className="v">{data.checks_30d}</span>
              <span className="small muted">dont {data.fingerprint_30d} en mode empreinte{data.running ? ` · ${data.running} en cours` : ''}</span>
            </div>
            <div className="card kpi">
              <span className="muted small">Vulnérabilités prouvées</span>
              <span className="v" style={{ color: 'var(--red)' }}>{data.proved_30d}</span>
              <span className="small muted">canari déclenché par la cible</span>
            </div>
            <div className="card kpi">
              <span className="muted small">Probables ou exposés</span>
              <span className="v" style={{ color: 'var(--purple)' }}>{data.probable_30d}</span>
              <span className="small muted">version ou surface exposée, sans preuve active</span>
            </div>
          </section>
          <div className="row">
            <section className="card col-2">
              <div className="card-head">
                <h2>Derniers verdicts</h2>
                <Link to="/checks" className="small">Tous les checks</Link>
              </div>
              {data.recent.length === 0 ? (
                <p className="muted">Aucun check pour l'instant. Commencez par <Link to="/assets/nouveau">déclarer un asset</Link>.</p>
              ) : (
                <div className="table-wrap">
                  <table className="t" style={{ minWidth: 560 }}>
                    <thead><tr><th>Asset</th><th>Checker</th><th>Verdict</th><th>Quand</th></tr></thead>
                    <tbody>
                      {data.recent.map((c) => (
                        <tr key={c.id} className="link" onClick={() => nav(`/checks/${c.id}`)}>
                          <td className="mono">{c.asset_host}</td>
                          <td><Link to={`/checks/${c.id}`}>{c.checker_name}</Link><span className="small dim"> · {c.cves[0]}</span></td>
                          <td><VerdictPill v={c.verdict} /></td>
                          <td className="muted">{ago(c.finished_at)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
            <div className="col-1 stack">
              <section className="card">
                <h2>Récepteur canari</h2>
                {rcv && (
                  <>
                    <div className="kv"><span>DNS autoritaire · {rcv.dns_addr}</span><span style={{ color: rcv.dns_up ? 'var(--green)' : 'var(--red)' }}>{rcv.dns_up ? 'En écoute' : 'Arrêté'}</span></div>
                    <div className="kv"><span>HTTP · {rcv.http_addr}</span><span style={{ color: rcv.http_up ? 'var(--green)' : 'var(--red)' }}>{rcv.http_up ? 'En écoute' : 'Arrêté'}</span></div>
                    <div className="kv"><span>Zone</span><span className="mono break">{rcv.zone}</span></div>
                  </>
                )}
                <div className="kv"><span>Dernier callback</span><span>{ago(data.last_callback)}</span></div>
                <Link to="/callbacks" className="small">Voir le journal des callbacks</Link>
              </section>
              <section className="card">
                <h2>Preuves à faire ou renouveler</h2>
                {data.renew.length === 0 && <p className="muted small" style={{ margin: 0 }}>Toutes les preuves sont valides.</p>}
                {data.renew.map((a) => {
                  const d = daysLeft(a.proof_valid_until)
                  return (
                    <div key={a.id} className="kv">
                      <Link to={`/assets/${a.id}`} className="mono" style={{ color: 'var(--text)' }}>{a.host}</Link>
                      <span style={{ color: 'var(--accent)' }}>{a.owned && d !== null ? `expire dans ${d} j` : a.proof_status === 'failed' ? 'échec' : 'à prouver'}</span>
                    </div>
                  )
                })}
                <Link to="/assets" className="small">Gérer les assets</Link>
              </section>
            </div>
          </div>
        </>
      )}
    </>
  )
}
