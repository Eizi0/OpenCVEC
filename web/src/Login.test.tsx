import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { Login } from './pages/Login'

describe('Login', () => {
  it('passe à l’étape TOTP quand le serveur la demande', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{"mfa_required":true}', { status: 200 })))
    const done = vi.fn()
    render(<Login onDone={done} />)
    fireEvent.change(screen.getByLabelText('Adresse e-mail'), { target: { value: 'a@b.fr' } })
    fireEvent.change(screen.getByLabelText('Mot de passe'), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: 'Se connecter' }))
    await waitFor(() => expect(screen.getByLabelText('Code TOTP')).toBeInTheDocument())
    expect(done).not.toHaveBeenCalled()
  })
  it('affiche l’erreur de connexion', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{"error":"adresse e-mail ou mot de passe incorrect"}', { status: 401 })))
    render(<Login onDone={vi.fn()} />)
    fireEvent.change(screen.getByLabelText('Adresse e-mail'), { target: { value: 'a@b.fr' } })
    fireEvent.change(screen.getByLabelText('Mot de passe'), { target: { value: 'x' } })
    fireEvent.click(screen.getByRole('button', { name: 'Se connecter' }))
    expect(await screen.findByRole('alert')).toHaveTextContent('incorrect')
  })
})
