import { useCallback, useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { api, post } from './api'
import { AuthContext, can } from './auth'
import { Layout } from './components/Layout'
import { Loading } from './components/ui'
import { Account } from './pages/Account'
import { Admin } from './pages/Admin'
import { AssetDetail, AssetNew, Assets } from './pages/Assets'
import { Catalog } from './pages/Catalog'
import { CampaignView, Campaigns, CheckResult, Launch } from './pages/Checks'
import { Dashboard } from './pages/Dashboard'
import { Login } from './pages/Login'
import { Audit, Callbacks, Reports } from './pages/Trace'
import type { Me } from './types'

export function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined)
  const refresh = useCallback(async () => {
    try {
      setMe(await api<Me>('/api/me'))
    } catch {
      setMe(null)
    }
  }, [])
  const logout = useCallback(async () => {
    try { await post('/api/logout') } finally { setMe(null) }
  }, [])
  useEffect(() => {
    void refresh()
    const off = () => setMe(null)
    window.addEventListener('opencvec:unauthorized', off)
    return () => window.removeEventListener('opencvec:unauthorized', off)
  }, [refresh])

  if (me === undefined) return <div style={{ padding: 40 }}><Loading /></div>
  if (me === null) return <Login onDone={() => void refresh()} />
  const mfaGate = me.require_mfa && !me.user.totp_enabled
  const analyst = can(me.user.role, 'analyst')
  const admin = can(me.user.role, 'admin')
  return (
    <AuthContext.Provider value={{ me, refresh, logout }}>
      <BrowserRouter>
        <Routes>
          <Route element={<Layout />}>
            {mfaGate ? (
              <Route path="*" element={<Account />} />
            ) : (
              <>
                <Route index element={<Dashboard />} />
                <Route path="assets" element={<Assets />} />
                {analyst && <Route path="assets/nouveau" element={<AssetNew />} />}
                <Route path="assets/:id" element={<AssetDetail />} />
                <Route path="catalogue" element={<Catalog />} />
                <Route path="checks" element={<Campaigns />} />
                {analyst && <Route path="checks/nouveau" element={<Launch />} />}
                <Route path="checks/:id" element={<CheckResult />} />
                <Route path="campagnes/:id" element={<CampaignView />} />
                <Route path="callbacks" element={<Callbacks />} />
                <Route path="rapports" element={<Reports />} />
                {admin && <Route path="audit" element={<Audit />} />}
                {admin && <Route path="admin" element={<Admin />} />}
                <Route path="compte" element={<Account />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </>
            )}
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthContext.Provider>
  )
}
