import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import { Plugins } from './pages/Plugins'

const preview = {
  id: 'ssh-test', name: 'SSHoleChecker', version: '1.0.0', cves: ['CVE-2099-0001'], mode: 'canary', product: 'OpenSSH',
  description: 'd', sent: 's', steps: ['a · TCP 22'], requires_file_canary: true, sha256: 'ab'.repeat(32),
  signed: false, publisher: '', signature_error: 'plugin non signé', installable: false, content: 'id: ssh-test',
}

describe('Plugins', () => {
  it('montre la revue et bloque un plugin non signé hors mode développeur', async () => {
    vi.stubGlobal('fetch', vi.fn(async (url: string) => {
      if (url === '/api/plugins/preview') return new Response(JSON.stringify(preview), { status: 200 })
      return new Response('[]', { status: 200 })
    }))
    render(<MemoryRouter><Plugins /></MemoryRouter>)
    fireEvent.click(screen.getByRole('tab', { name: 'Importer' }))
    fireEvent.change(screen.getByLabelText('URL https du fichier YAML'), { target: { value: 'https://exemple.fr/p.yaml' } })
    fireEvent.click(screen.getByRole('button', { name: 'Examiner' }))
    expect(await screen.findByText('Non signé ou signature refusée')).toBeInTheDocument()
    expect(screen.getByText(/Requis : à déposer/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Installer' })).toBeDisabled()
  })
})
