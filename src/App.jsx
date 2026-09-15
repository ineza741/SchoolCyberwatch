import { useEffect, useState } from 'react'
import AppShell from './components/AppShell'
import DashboardPage from './pages/DashboardPage'
import LandingPage from './pages/LandingPage'
import LoginPage from './pages/LoginPage'

const pageFromHash = () => window.location.hash.replace('#/', '') || 'landing'

export default function App() {
  const [page, setPage] = useState(pageFromHash)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  useEffect(() => { const updatePage = () => setPage(pageFromHash()); window.addEventListener('hashchange', updatePage); return () => window.removeEventListener('hashchange', updatePage) }, [])
  const navigate = (nextPage) => { window.location.hash = `/${nextPage}` }
  const signIn = () => { setIsAuthenticated(true); navigate('dashboard') }
  const signOut = () => { setIsAuthenticated(false); navigate('login') }
  if (page === 'dashboard') return isAuthenticated ? <AppShell onLogout={signOut}><DashboardPage /></AppShell> : <LoginPage onLogin={signIn} onBack={() => navigate('landing')} />
  if (page === 'login') return <LoginPage onLogin={signIn} onBack={() => navigate('landing')} />
  return <LandingPage onLogin={() => navigate('login')} />
}
