import { Fragment, useState, type FormEvent } from 'react'
import { del, post, put } from '../api'
import { ErrorBox, Loading, ModePill, useLoad } from '../components/ui'
import { dateTime } from '../format'
import type { PluginPreview, PluginRow, PublisherRow, RegistryEntry } from '../types'

type Tab = 'installed' | 'registry' | 'import' | 'publishers'

export function Plugins() {
  const [tab, setTab] = useState<Tab>('installed')
  const [preview, setPreview] = useState<{ pv: PluginPreview; input: Record<string, string> } | null>(null)
  const openPreview = (pv: PluginPreview, input: Record<string, string>) => { setPreview({ pv, input }); setTab('import') }
  return (
    <>
      <header className="page-head">
        <div>
          <h1>Plugins</h1>
          <p className="lead">Ajoutez un check pour une nouvelle CVE sans mettre à jour OpenCVEC. Un plugin est un fichier YAML signé : ses requêtes ne peuvent viser que l'asset du check, et la preuve passe toujours par un canari (callback DNS/HTTP ou canari fichier relu).</p>
        </div>
      </header>
      <div role="tablist" aria-label="Sections" className="tabline">
        {([['installed', 'Installés'], ['registry', 'Catalogue officiel'], ['import', 'Importer'], ['publishers', 'Éditeurs de confiance']] as [Tab, string][]).map(([id, l]) => (
          <button key={id} type="button" role="tab" aria-selected={tab === id} className={tab === id ? 'on' : ''} onClick={() => setTab(id)}>{l}</button>
        ))}
      </div>
      {tab === 'installed' && <Installed />}
      {tab === 'registry' && <Registry onPreview={openPreview} />}
      {tab === 'import' && <Import initial={preview} onDone={() => { setPreview(null); setTab('installed') }} />}
      {tab === 'publishers' && <Publishers />}
    </>
  )
}

function Installed() {
  const { data, error, reload } = useLoad<PluginRow[]>('/api/plugins')
  const [err, setErr] = useState('')
  const [open, setOpen] = useState<string | null>(null)
  if (!data) return error ? <ErrorBox error={error} /> : <Loading />
  return (
    <section className="stack">
      <ErrorBox error={err} />
      {data.length === 0 ? <p className="muted">Aucun plugin installé. Parcourez le catalogue officiel ou importez un fichier.</p> : (
        <div className="card flush table-wrap">
          <table className="t" style={{ minWidth: 860 }}>
            <thead><tr><th>Plugin</th><th>Signature</th><th>Source</th><th>Installé</th><th>Actions</th></tr></thead>
            <tbody>
              {data.map((p) => (
                <Fragment key={p.id}>
                  <tr style={{ opacity: p.enabled ? 1 : 0.55 }}>
                    <td><strong>{p.name}</strong> <span className="small dim">v{p.version}</span><div className="sub mono">{p.id}</div></td>
                    <td>{p.signed ? <span className="pill green">Signé · {p.publisher}</span> : <span className="pill red">Non signé</span>}<div className="sub mono" title={p.sha256}>sha256 {p.sha256.slice(0, 12)}…</div></td>
                    <td className="small muted break" style={{ maxWidth: 260 }}>{p.source}</td>
                    <td className="muted">{dateTime(p.installed_at)}<div className="sub">{p.installed_by}</div></td>
                    <td>
                      <div className="btns" style={{ gap: 6 }}>
                        <button type="button" className="btn small" onClick={() => setOpen(open === p.id ? null : p.id)}>{open === p.id ? 'Masquer' : 'Voir le YAML'}</button>
                        <button type="button" className="btn small" onClick={async () => {
                          try { await put(`/api/plugins/${p.id}`, { enabled: !p.enabled }); await reload() } catch (e) { setErr((e as Error).message) }
                        }}>{p.enabled ? 'Désactiver' : 'Activer'}</button>
                        <button type="button" className="btn small danger" onClick={async () => {
                          if (!window.confirm(`Désinstaller ${p.name} ? L'historique de ses checks est conservé.`)) return
                          try { await del(`/api/plugins/${p.id}`); await reload() } catch (e) { setErr((e as Error).message) }
                        }}>Désinstaller</button>
                      </div>
                    </td>
                  </tr>
                  {open === p.id && <tr><td colSpan={5}><pre className="code">{p.content}</pre></td></tr>}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function Registry({ onPreview }: { onPreview: (pv: PluginPreview, input: Record<string, string>) => void }) {
  const { data, error } = useLoad<{ registry: string; publisher: string; plugins: RegistryEntry[] }>('/api/plugins/registry')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState('')
  return (
    <section className="stack">
      {error && (
        <div className="notice warn" role="status">
          <strong>Catalogue injoignable</strong>
          <span>{error}</span>
          <span className="small muted">Sans accès Internet, téléchargez le plugin et sa signature (.sig) depuis le dépôt GitHub, puis utilisez l'onglet « Importer ». L'adresse du catalogue se règle avec OPENCVEC_PLUGIN_REGISTRY.</span>
        </div>
      )}
      <ErrorBox error={err} />
      {!data && !error && <Loading />}
      {data && <p className="hint">Dépôt : <span className="mono">{data.registry}</span> · éditeur {data.publisher}</p>}
      <div className="grid-cards">
        {data?.plugins.map((p) => (
          <article key={p.id} className="card">
            <div className="card-head" style={{ alignItems: 'flex-start' }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <h2 style={{ fontFamily: 'var(--display)', fontSize: 18 }}>{p.name}</h2>
                <span className="mono" style={{ color: '#aeb7c4' }}>{p.cves.join(' · ')} · v{p.version}</span>
              </div>
              <ModePill mode={p.mode} />
            </div>
            <p className="small" style={{ margin: 0, color: 'var(--text-2)', lineHeight: 1.55 }}>{p.description}</p>
            <span className="small muted">{p.product}</span>
            <button type="button" className={`btn small ${p.installed === p.version ? '' : 'primary'}`} style={{ marginTop: 'auto' }} disabled={busy === p.id}
              onClick={async () => {
                setBusy(p.id)
                setErr('')
                try { onPreview(await post<PluginPreview>('/api/plugins/preview', { url: p.url }), { url: p.url }) } catch (e) { setErr((e as Error).message) } finally { setBusy('') }
              }}>
              {p.installed ? (p.installed === p.version ? 'Installé · revoir' : `Mettre à jour (${p.installed} → ${p.version})`) : 'Examiner et installer'}
            </button>
          </article>
        ))}
      </div>
    </section>
  )
}

function readFile(f: File): Promise<string> {
  return new Promise((ok, ko) => {
    const r = new FileReader()
    r.onload = () => ok(String(r.result))
    r.onerror = () => ko(r.error)
    r.readAsText(f)
  })
}

function Import({ initial, onDone }: { initial: { pv: PluginPreview; input: Record<string, string> } | null; onDone: () => void }) {
  const [url, setUrl] = useState('')
  const [content, setContent] = useState('')
  const [sig, setSig] = useState('')
  const [pv, setPv] = useState<PluginPreview | null>(initial?.pv ?? null)
  const [input, setInput] = useState<Record<string, string>>(initial?.input ?? {})
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)

  async function inspect(e: FormEvent) {
    e.preventDefault()
    setErr('')
    setPv(null)
    const body: Record<string, string> = url ? { url } : { content, signature: sig }
    try {
      setPv(await post<PluginPreview>('/api/plugins/preview', body))
      setInput(body)
    } catch (e2) {
      setErr((e2 as Error).message)
    }
  }
  return (
    <div className="row">
      <form className="card col-1" onSubmit={inspect}>
        <h2>Source du plugin</h2>
        <div className="field">
          <label htmlFor="purl">URL https du fichier YAML</label>
          <input id="purl" className="input mono" placeholder="https://raw.githubusercontent.com/…/plugins/x.yaml" value={url} onChange={(e) => setUrl(e.target.value)} />
          <p className="hint">La signature est cherchée à la même adresse, suffixée de « .sig ».</p>
        </div>
        <span className="label">ou fichiers locaux</span>
        <div className="field">
          <label htmlFor="pfile">Plugin (.yaml)</label>
          <input id="pfile" type="file" accept=".yaml,.yml" className="input" style={{ paddingTop: 10 }} onChange={async (e) => { const f = e.target.files?.[0]; if (f) { setContent(await readFile(f)); setUrl('') } }} />
        </div>
        <div className="field">
          <label htmlFor="psig">Signature (.sig)</label>
          <input id="psig" type="file" accept=".sig" className="input" style={{ paddingTop: 10 }} onChange={async (e) => { const f = e.target.files?.[0]; if (f) setSig(await readFile(f)) }} />
        </div>
        <ErrorBox error={err} />
        <div className="btns"><button className="btn primary" type="submit" disabled={!url && !content}>Examiner</button></div>
      </form>
      <section className="card col-2">
        <h2>Revue avant installation</h2>
        {!pv ? <p className="muted" style={{ margin: 0 }}>Choisissez un plugin : son contenu, ses étapes et sa signature s'affichent ici avant toute installation.</p> : (
          <>
            <div className="card-head">
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                <h3 style={{ fontSize: 18, fontFamily: 'var(--display)' }}>{pv.name} <span className="small dim">v{pv.version}</span></h3>
                <span className="mono small muted">{pv.id} · {pv.cves.join(', ')}</span>
              </div>
              <ModePill mode={pv.mode} />
            </div>
            {pv.signed
              ? <div className="notice ok"><strong>Signature valide · {pv.publisher}</strong><span className="small mono">sha256 {pv.sha256}</span></div>
              : <div className="notice err"><strong>Non signé ou signature refusée</strong><span>{pv.signature_error}</span>{pv.installable && <span className="small">Le mode développeur est actif : l'installation reste possible et sera journalisée.</span>}</div>}
            {pv.replaces && <div className="notice warn"><strong>Mise à jour</strong><span>Remplace la version {pv.replaces} installée.</span></div>}
            <p style={{ margin: 0, color: 'var(--text-2)' }}>{pv.description}</p>
            <dl className="grid">
              <dt>Produit</dt><dd>{pv.product}</dd>
              <dt>Envoyé à la cible</dt><dd>{pv.sent}</dd>
              <dt>Étapes</dt><dd>{pv.steps.map((s) => <div key={s} className="mono small">{s}</div>)}</dd>
              <dt>Canari fichier</dt><dd>{pv.requires_file_canary ? 'Requis : à déposer sur chaque asset testé' : 'Non requis'}</dd>
            </dl>
            <details><summary className="small" style={{ cursor: 'pointer', color: 'var(--accent)' }}>Contenu complet du plugin</summary><pre className="code">{pv.content}</pre></details>
            <div className="btns">
              <button className="btn primary" type="button" disabled={!pv.installable || busy} onClick={async () => {
                setBusy(true)
                setErr('')
                try { await post('/api/plugins', input); onDone() } catch (e) { setErr((e as Error).message) } finally { setBusy(false) }
              }}>{busy ? 'Installation…' : pv.replaces ? 'Mettre à jour' : 'Installer'}</button>
            </div>
          </>
        )}
      </section>
    </div>
  )
}

function Publishers() {
  const { data, error, reload } = useLoad<PublisherRow[]>('/api/publishers')
  const [name, setName] = useState('')
  const [key, setKey] = useState('')
  const [err, setErr] = useState('')
  return (
    <section className="stack">
      <p className="lead">Seuls les plugins signés par un éditeur listé ici sont installés et chargés. Retirer un éditeur désactive aussitôt ses plugins. Pour signer vos propres plugins : <span className="mono">opencvec plugin keygen</span> puis <span className="mono">opencvec plugin sign</span>.</p>
      <form className="card" style={{ flexDirection: 'row', flexWrap: 'wrap', alignItems: 'flex-end', gap: 12 }} onSubmit={async (e) => {
        e.preventDefault()
        setErr('')
        try { await post('/api/publishers', { name, public_key: key }); setName(''); setKey(''); await reload() } catch (e2) { setErr((e2 as Error).message) }
      }}>
        <div className="field" style={{ flex: '1 1 200px' }}><label htmlFor="pn">Nom</label><input id="pn" className="input" required value={name} onChange={(e) => setName(e.target.value)} placeholder="Équipe sécurité interne" /></div>
        <div className="field" style={{ flex: '3 1 360px' }}><label htmlFor="pk">Clé publique</label><input id="pk" className="input mono" required value={key} onChange={(e) => setKey(e.target.value)} placeholder="opencvec-pub-v1 …" /></div>
        <button className="btn primary" type="submit">Approuver</button>
      </form>
      <ErrorBox error={err || error} />
      {!data ? <Loading /> : (
        <div className="card flush table-wrap">
          <table className="t" style={{ minWidth: 720 }}>
            <thead><tr><th>Éditeur</th><th>Clé</th><th>Ajouté</th><th></th></tr></thead>
            <tbody>
              {data.map((p) => (
                <tr key={p.id}>
                  <td>{p.name} {p.builtin && <span className="pill blue">intégré</span>}</td>
                  <td className="mono small break">{p.key_id}<div className="sub">{p.public_key}</div></td>
                  <td className="muted">{dateTime(p.created_at)}<div className="sub">{p.added_by || 'installation'}</div></td>
                  <td>{!p.builtin && <button type="button" className="btn small danger" onClick={async () => {
                    if (!window.confirm(`Retirer ${p.name} ? Ses plugins ne seront plus chargés.`)) return
                    try { await del(`/api/publishers/${p.id}`); await reload() } catch (e) { setErr((e as Error).message) }
                  }}>Retirer</button>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
