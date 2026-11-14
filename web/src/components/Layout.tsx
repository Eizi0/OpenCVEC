import { NavLink, Outlet } from 'react-router-dom'
import { can, useAuth } from '../auth'
import { roleLabel } from '../format'
import type { Receiver } from '../types'
import { LangSwitch, Logo, useLoad } from './ui'

function initials(s: string) {
  const parts = s.split(/[\s@.]+/).filter(Boolean)
  return ((parts[0]?.[0] ?? '') + (parts[1]?.[0] ?? '')).toUpperCase()
}

export function Layout() {
  const { me, logout } = useAuth()
  const { data: rcv } = useLoad<Receiver>('/api/receiver', 30000)
  const role = me.user.role
  const up = rcv ? rcv.dns_up && rcv.http_up : true
  return (
    <div className="app">
      <nav className="sidebar" aria-label="Navigation principale">
        <NavLink to="/" className="brand" end>
          <Logo />
          <span>OpenCVEC</span>
        </NavLink>
        <div className="nav">
          <span className="nav-title">Vérifier</span>
          <NavLink to="/" end>Vue d'ensemble</NavLink>
          <NavLink to="/assets">Assets</NavLink>
          <NavLink to="/catalogue">Catalogue des checkers</NavLink>
          <NavLink to="/checks">Checks</NavLink>
          <span className="nav-title">Tracer</span>
          <NavLink to="/callbacks">Callbacks canari</NavLink>
          <NavLink to="/rapports">Rapports</NavLink>
          {can(role, 'admin') && <NavLink to="/audit">Journal d'audit</NavLink>}
          {can(role, 'admin') && <NavLink to="/plugins">Plugins</NavLink>}
          {can(role, 'admin') && <NavLink to="/admin">Administration</NavLink>}
        </div>
        <div className="side-foot">
          <div className="receiver-box">
            <span className="nav-title" style={{ padding: 0 }}>Récepteur canari</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
              <span className={`dot ${up ? '' : 'off'}`} />
              {rcv ? (up ? 'DNS + HTTP actifs' : `${rcv.dns_up ? '' : 'DNS arrêté '}${rcv.http_up ? '' : 'HTTP arrêté'}`) : '…'}
            </span>
            <span className="mono small" style={{ color: '#aeb7c4', wordBreak: 'break-all' }}>{me.canary_zone}</span>
          </div>
          <NavLink to="/compte" className="who" style={{ color: 'var(--text)' }}>
            <span className="avatar">{initials(me.user.name || me.user.email)}</span>
            <span style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}>
              <span style={{ fontSize: 13, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis' }}>{me.user.name || me.user.email}</span>
              <span className="small dim">{roleLabel[role]}</span>
            </span>
          </NavLink>
          <div className="btns" style={{ gap: 8 }}>
            <button type="button" className="btn small" onClick={() => void logout()}>Se déconnecter</button>
            <LangSwitch />
          </div>
          <span className="small dim" style={{ padding: '0 8px' }}>OpenCVEC {me.version}</span>
        </div>
      </nav>
      <main className="main">
        <Outlet />
      </main>
    </div>
  )
}
