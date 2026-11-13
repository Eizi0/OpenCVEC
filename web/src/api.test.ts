import { describe, expect, it, vi } from 'vitest'
import { api, ApiError, post } from './api'

describe('api', () => {
  it('envoie l’en-tête anti-CSRF et le JSON', async () => {
    const f = vi.fn().mockResolvedValue(new Response('{"ok":true}', { status: 200 }))
    vi.stubGlobal('fetch', f)
    await post('/api/assets', { host: 'x' })
    const [, init] = f.mock.calls[0]
    expect(init.headers['X-OpenCVEC']).toBe('1')
    expect(init.body).toBe('{"host":"x"}')
  })
  it('remonte le message d’erreur du serveur', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{"error":"propriété non prouvée"}', { status: 403 })))
    await expect(api('/api/campaigns')).rejects.toEqual(new ApiError(403, 'propriété non prouvée'))
  })
  it('signale une session expirée', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{"error":"x"}', { status: 401 })))
    const seen = vi.fn()
    window.addEventListener('opencvec:unauthorized', seen)
    await expect(api('/api/me')).rejects.toBeInstanceOf(ApiError)
    expect(seen).toHaveBeenCalled()
  })
})
