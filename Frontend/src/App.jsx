import { useEffect, useState } from 'react'
import AppShell from './components/AppShell'
import DashboardPage from './pages/DashboardPage'
import LandingPage from './pages/LandingPage'
import LoginPage from './pages/LoginPage'
import ComputersPage from './pages/ComputersPage'
import AlertsPage from './pages/AlertsPage'
import IncidentsPage from './pages/IncidentsPage'
import ReportsPage from './pages/ReportsPage'

const pageFromHash = () => window.location.hash.replace('#/', '') || 'landing'

export default function App() {
  const [page, setPage] = useState(pageFromHash)
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [isDark, setIsDark] = useState(false)
  
  useEffect(() => { 
    const updatePage = () => setPage(pageFromHash()); 
    window.addEventListener('hashchange', updatePage); 
    return () => window.removeEventListener('hashchange', updatePage) 
  }, [])
  
  const navigate = (nextPage) => { window.location.hash = `/${nextPage}` }
  const signIn = () => { setIsAuthenticated(true); navigate('dashboard') }
  const signOut = () => { setIsAuthenticated(false); navigate('login') }
  const toggleTheme = () => setIsDark((value) => !value)
  
  const renderAuthenticatedPage = () => {
    switch(page) {
      case 'dashboard': return <DashboardPage />
      case 'computers': return <ComputersPage />
      case 'alerts': return <AlertsPage />
      case 'incidents': return <IncidentsPage />
      case 'reports': return <ReportsPage />
      default: return <DashboardPage /> // fallback for authenticated unknown routes
    }
  }

  const isAuthRoute = ['dashboard', 'computers', 'alerts', 'incidents', 'reports'].includes(page)

  if (isAuthRoute) {
    return <div className={isDark ? 'theme-dark' : ''}>{isAuthenticated ? <AppShell activePage={page} isDark={isDark} onLogout={signOut} onToggleTheme={toggleTheme} onNavigate={navigate}>{renderAuthenticatedPage()}</AppShell> : <LoginPage isDark={isDark} onLogin={signIn} onBack={() => navigate('landing')} onToggleTheme={toggleTheme} />}</div>
  }
  
  if (page === 'login') return <div className={isDark ? 'theme-dark' : ''}><LoginPage isDark={isDark} onLogin={signIn} onBack={() => navigate('landing')} onToggleTheme={toggleTheme} /></div>
  
  return <div className={isDark ? 'theme-dark' : ''}><LandingPage isDark={isDark} onLogin={() => navigate('login')} onToggleTheme={toggleTheme} /></div>
}
