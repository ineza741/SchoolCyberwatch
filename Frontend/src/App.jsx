import { useEffect, useState } from 'react'
import AppShell from './components/AppShell'
import DashboardPage from './pages/DashboardPage'
import LandingPage from './pages/LandingPage'
import LoginPage from './pages/LoginPage'
import { clearStoredAuth, getStoredAuth } from './services/auth'
import ComputersPage from './pages/ComputersPage'
import AlertsPage from './pages/AlertsPage'
import IncidentsPage from './pages/IncidentsPage'
import ReportsPage from './pages/ReportsPage'

const pageFromHash = () => window.location.hash.replace('#/', '') || 'landing'
const PROTECTED_PAGES = ['dashboard', 'computers', 'alerts', 'incidents', 'reports']

export default function App() {
  const [page, setPage] = useState(pageFromHash)
  const [isAuthenticated, setIsAuthenticated] = useState(() => Boolean(getStoredAuth()))
  const [user, setUser] = useState(() => getStoredAuth())
  const [isDark, setIsDark] = useState(false)

  useEffect(() => {
    const updatePage = () => setPage(pageFromHash())
    window.addEventListener('hashchange', updatePage)
    return () => window.removeEventListener('hashchange', updatePage)
  }, [])

  const navigate = (nextPage) => { window.location.hash = `/${nextPage}` }

  const signIn = (auth) => {
    setUser(auth)
    setIsAuthenticated(true)
    navigate('dashboard')
  }

  const signOut = () => {
    clearStoredAuth()
    setUser(null)
    setIsAuthenticated(false)
    navigate('login')
  }

  const toggleTheme = () => setIsDark((value) => !value)

  // Route protection: unauthenticated users can never render protected pages.
  if (!isAuthenticated && PROTECTED_PAGES.includes(page)) {
    return (
      <div className={isDark ? 'theme-dark' : ''}>
        <LoginPage isDark={isDark} onLogin={signIn} onBack={() => navigate('landing')} onToggleTheme={toggleTheme} />
      </div>
    )
  }

  if (page === 'dashboard') {
    return (
      <div className={isDark ? 'theme-dark' : ''}>
        <AppShell activePage="dashboard" user={user} onNavigate={navigate} isDark={isDark} onLogout={signOut} onToggleTheme={toggleTheme}>
          <DashboardPage />
        </AppShell>
      </div>
    )
  }

  if (page === 'login') {
    return (
      <div className={isDark ? 'theme-dark' : ''}>
        <LoginPage isDark={isDark} onLogin={signIn} onBack={() => navigate('landing')} onToggleTheme={toggleTheme} />
      </div>
    )
  }

  if (page === 'computers') {
    return (
      <div className={isDark ? 'theme-dark' : ''}>
        <AppShell activePage="computers" user={user} onNavigate={navigate} isDark={isDark} onLogout={signOut} onToggleTheme={toggleTheme}>
          <ComputersPage />
        </AppShell>
      </div>
    )
  }

  if (page === 'alerts') {
    return (
      <div className={isDark ? 'theme-dark' : ''}>
        <AppShell activePage="alerts" user={user} onNavigate={navigate} isDark={isDark} onLogout={signOut} onToggleTheme={toggleTheme}>
          <AlertsPage />
        </AppShell>
      </div>
    )
  }

  if (page === 'incidents') {
    return (
      <div className={isDark ? 'theme-dark' : ''}>
        <AppShell activePage="incidents" user={user} onNavigate={navigate} isDark={isDark} onLogout={signOut} onToggleTheme={toggleTheme}>
          <IncidentsPage />
        </AppShell>
      </div>
    )
  }

  if (page === 'reports') {
    return (
      <div className={isDark ? 'theme-dark' : ''}>
        <AppShell activePage="reports" user={user} onNavigate={navigate} isDark={isDark} onLogout={signOut} onToggleTheme={toggleTheme}>
          <ReportsPage />
        </AppShell>
      </div>
    )
  }

  const shellPages = []
  if (shellPages.includes(page)) {
    return (
      <div className={isDark ? 'theme-dark' : ''}>
        <AppShell activePage={page} user={user} onNavigate={navigate} isDark={isDark} onLogout={signOut} onToggleTheme={toggleTheme}>
          <PlaceholderPage
            eyebrow="School CyberWatch"
            title={page.charAt(0).toUpperCase() + page.slice(1)}
            description="This page will connect to live security data in an upcoming phase."
          />
        </AppShell>
      </div>
    )
  }

  return (
    <div className={isDark ? 'theme-dark' : ''}>
      <LandingPage isDark={isDark} onLogin={() => navigate('login')} onToggleTheme={toggleTheme} />
    </div>
  )
}
