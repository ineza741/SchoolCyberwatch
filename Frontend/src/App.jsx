import { useEffect, useState } from 'react'
import AppShell from './components/AppShell'
import DashboardPage from './pages/DashboardPage'
import LandingPage from './pages/LandingPage'
import LoginPage from './pages/LoginPage'
import { clearStoredAuth, getStoredAuth } from './services/auth'
import { onAuthExpired } from './services/api'
import ComputersPage from './pages/ComputersPage'
import AlertsPage from './pages/AlertsPage'
import IncidentsPage from './pages/IncidentsPage'
import ReportsPage from './pages/ReportsPage'
import NetworkPage from './pages/NetworkPage'

const pageFromHash = () => window.location.hash.replace('#/', '') || 'landing'
const PROTECTED_PAGES = ['dashboard', 'computers', 'alerts', 'incidents', 'reports', 'network']

export default function App() {
  const [page, setPage] = useState(pageFromHash)
  const [isAuthenticated, setIsAuthenticated] = useState(() => Boolean(getStoredAuth()))
  const [user, setUser] = useState(() => getStoredAuth())
  const [isDark, setIsDark] = useState(false)
  const [sessionNotice, setSessionNotice] = useState('')

  useEffect(() => {
    const updatePage = () => setPage(pageFromHash())
    window.addEventListener('hashchange', updatePage)
    return () => window.removeEventListener('hashchange', updatePage)
  }, [])

  // Any API call that hits HTTP 401 clears the stored JWT and fires this
  // event; App then shows the login page once, with a friendly notice.
  // No redirect loop: the event only fires from real API responses.
  useEffect(() => {
    return onAuthExpired(() => {
      clearStoredAuth()
      setUser(null)
      setIsAuthenticated(false)
      setSessionNotice('Your session has expired. Please sign in again.')
      window.location.hash = '/login'
    })
  }, [])

  const navigate = (nextPage) => { window.location.hash = `/${nextPage}` }

  const signIn = (auth) => {
    setUser(auth)
    setIsAuthenticated(true)
    setSessionNotice('')
    navigate('dashboard')
  }

  const signOut = () => {
    clearStoredAuth()
    setUser(null)
    setIsAuthenticated(false)
    navigate('login')
  }

  const toggleTheme = () => setIsDark((value) => !value)

  const loginPage = (
    <div className={isDark ? 'theme-dark' : ''}>
      <LoginPage
        isDark={isDark}
        onLogin={signIn}
        onBack={() => navigate('landing')}
        onToggleTheme={toggleTheme}
        notice={sessionNotice}
      />
    </div>
  )

  // Route protection: unauthenticated users can never render protected pages.
  if (!isAuthenticated && PROTECTED_PAGES.includes(page)) {
    return loginPage
  }

  if (page === 'login') {
    return loginPage
  }

  const shellPage = (activePage, PageComponent) => (
    <div className={isDark ? 'theme-dark' : ''}>
      <AppShell
        activePage={activePage}
        user={user}
        onNavigate={navigate}
        isDark={isDark}
        onLogout={signOut}
        onToggleTheme={toggleTheme}
      >
        <PageComponent />
      </AppShell>
    </div>
  )

  if (page === 'dashboard') return shellPage('dashboard', DashboardPage)
  if (page === 'computers') return shellPage('computers', ComputersPage)
  if (page === 'alerts') return shellPage('alerts', AlertsPage)
  if (page === 'incidents') return shellPage('incidents', IncidentsPage)
  if (page === 'reports') return shellPage('reports', ReportsPage)
  if (page === 'network') return shellPage('network', NetworkPage)

  return (
    <div className={isDark ? 'theme-dark' : ''}>
      <LandingPage isDark={isDark} onLogin={() => navigate('login')} onToggleTheme={toggleTheme} />
    </div>
  )
}
