// Client HTTP minimal : JSON, cookies de session et en-tête anti-CSRF.

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

export async function api<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const res = await fetch(path, {
    method: init.method ?? 'GET',
    credentials: 'same-origin',
    headers: {
      'X-OpenCVEC': '1',
      ...(init.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    },
    body: init.body !== undefined ? JSON.stringify(init.body) : undefined,
  })
  const text = await res.text()
  let data: unknown = null
  try {
    data = text ? JSON.parse(text) : null
  } catch {
    data = null
  }
  if (!res.ok) {
    const msg = (data as { error?: string } | null)?.error || `Erreur ${res.status}`
    if (res.status === 401 && !path.startsWith('/api/login')) {
      window.dispatchEvent(new CustomEvent('opencvec:unauthorized'))
    }
    throw new ApiError(res.status, msg)
  }
  return data as T
}

export const post = <T>(path: string, body: unknown = {}) => api<T>(path, { method: 'POST', body })
export const put = <T>(path: string, body: unknown = {}) => api<T>(path, { method: 'PUT', body })
export const del = <T>(path: string) => api<T>(path, { method: 'DELETE' })
