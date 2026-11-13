import { createContext, useContext } from 'react'
import type { Me, Role } from './types'

export const AuthContext = createContext<{ me: Me; refresh: () => Promise<void>; logout: () => Promise<void> } | null>(null)

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('AuthContext absent')
  return ctx
}

const rank: Record<Role, number> = { viewer: 1, analyst: 2, admin: 3 }

export function can(role: Role, needed: Role) {
  return rank[role] >= rank[needed]
}
