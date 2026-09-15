import { useEffect, useState } from 'react'
import AppShell from './components/AppShell'
import DashboardPage from './pages/DashboardPage'
import LandingPage from './pages/LandingPage'
import LoginPage from './pages/LoginPage'

const pageFromHash = () => window.location.hash.replace('#/', '') || 'landing'

export default function App() {
  const [page, setPage] = useState(pageFromHash)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isDark, setIsDark] = useState(false)
  useEffect(() => { const updatePage = () => setPage(pageFromHash()); window.addEventListener('hashchange', updatePage); return () => window.removeEventListener('hashchange', updatePage) }, [])
  const navigate = (nextPage) => { window.location.hash = `/${nextPage}` }
  const signIn = () => { setIsAuthenticated(true); navigate('dashboard') }
  const signOut = () => { setIsAuthenticated(false); navigate('login') }
  const toggleTheme = () => setIsDark((value) => !value)
  if (page === 'dashboard') return <div className={isDark ? 'theme-dark' : ''}>{isAuthenticated ? <AppShell activePage="dashboard" isDark={isDark} onLogout={signOut} onToggleTheme={toggleTheme}><DashboardPage /></AppShell> : <LoginPage isDark={isDark} onLogin={signIn} onBack={() => navigate('landing')} onToggleTheme={toggleTheme} />}</div>
  if (page === 'login') return <div className={isDark ? 'theme-dark' : ''}><LoginPage isDark={isDark} onLogin={signIn} onBack={() => navigate('landing')} onToggleTheme={toggleTheme} /></div>
  return <div className={isDark ? 'theme-dark' : ''}><LandingPage isDark={isDark} onLogin={() => navigate('login')} onToggleTheme={toggleTheme} /></div>
}
