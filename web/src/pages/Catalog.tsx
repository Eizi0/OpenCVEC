import { useState } from 'react'
import { Link } from 'react-router-dom'
import { can, useAuth } from '../auth'
import { ErrorBox, Loading, ModePill, Tabs, useLoad } from '../components/ui'
import type { CheckerInfo } from '../types'

export function Catalog() {
  const { me } = useAuth()
  const { data, error } = useLoad<CheckerInfo[]>('/api/checkers')
  const [f, setF] = useState<'all' | 'canary' | 'fingerprint'>('all')
  const all = data ?? []
  const list = all.filter((c) => f === 'all' || c.mode === f)
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Catalogue des checkers</h1>
          <p className="lead">Les payloads sont figés dans chaque module : seul le nom d'hôte du canari y est injecté. Les failles qu'on ne peut prouver sans exploit réel (corruption mémoire, chaînes RCE récentes) sont vérifiées par empreinte, sans aucune charge.</p>
        </div>
      </header>
      <ErrorBox error={error} />
      <Tabs label="Filtrer par mode" value={f} onChange={setF} items={[
        ['all', `Tous · ${all.length}`],
        ['canary', `Preuve par canari · ${all.filter((c) => c.mode === 'canary').length}`],
        ['fingerprint', `Empreinte seule · ${all.filter((c) => c.mode === 'fingerprint').length}`],
      ]} />
      {!data && !error && <Loading />}
      <div className="grid-cards">
        {list.map((c) => (
          <article key={c.id} className="card">
            <div className="card-head" style={{ alignItems: 'flex-start' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <h2 style={{ fontFamily: 'var(--display)', fontSize: 18 }}>{c.name}</h2>
                <span className="mono" style={{ color: '#aeb7c4' }}>{c.cves.join(' · ')}</span>
              </div>
              <ModePill mode={c.mode} />
            </div>
            <p style={{ margin: 0, color: 'var(--text-2)', lineHeight: 1.55, fontSize: 13.5 }}>{c.description}</p>
            <dl className="grid" style={{ gridTemplateColumns: 'auto 1fr', fontSize: 12.5, gap: '6px 14px' }}>
              <dt>Produit</dt><dd>{c.product}</dd>
              <dt>Preuve</dt><dd>{c.proof}</dd>
              <dt>Envoyé</dt><dd>{c.sent}</dd>
              <dt>Module</dt><dd style={{ color: c.lab_validated ? 'var(--green)' : '#aeb7c4' }}>{c.lab_validated ? 'Validé en labo' : 'Non validé en labo'} · {c.lab_note}</dd>
            </dl>
            <details>
              <summary className="small" style={{ cursor: 'pointer', color: 'var(--accent)' }}>Remédiation et références</summary>
              <ol className="small muted" style={{ paddingLeft: 18, lineHeight: 1.6 }}>{c.remediation.map((r) => <li key={r}>{r}</li>)}</ol>
              <ul className="small" style={{ paddingLeft: 18, lineHeight: 1.6 }}>{c.references.map((r) => <li key={r}><a href={r} target="_blank" rel="noreferrer noopener" className="break">{r}</a></li>)}</ul>
            </details>
            {can(me.user.role, 'analyst') && <Link className="btn small" style={{ marginTop: 'auto' }} to={`/checks/nouveau?checker=${c.id}`}>Utiliser ce checker</Link>}
          </article>
        ))}
      </div>
    </>
  )
}
