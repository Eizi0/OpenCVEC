import '@fontsource-variable/inter'
import '@fontsource/space-grotesk/500.css'
import '@fontsource/space-grotesk/600.css'
import '@fontsource/space-grotesk/700.css'
import '@fontsource/jetbrains-mono/400.css'
import './styles.css'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
import { startI18n } from './i18n'

const root = document.getElementById('root')!
startI18n(root)
createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
