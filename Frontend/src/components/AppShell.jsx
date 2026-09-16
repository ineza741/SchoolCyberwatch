import BrandMark from './BrandMark'

const navigation = [
  { id: 'dashboard', label: 'Dashboard', icon: 'grid' },
  { id: 'computers', label: 'Computers', icon: 'computer' },
  { id: 'alerts', label: 'Security alerts', icon: 'shield' },
  { id: 'incidents', label: 'Incidents', icon: 'warning' },
  { id: 'reports', label: 'Reports', icon: 'report' },
]

function NavIcon({ name }) {
  const paths = {
    grid: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
    computer: <><rect x="3" y="4" width="18" height="12" rx="2" /><path d="M8 20h8M12 16v4" /></>,
    shield: <path d="M12 3 20 6v5c0 5-3.4 8.4-8 10-4.6-1.6-8-5-8-10V6l8-3Z" />,
    warning: <><path d="M10.3 4.4 3 17a2 2 0 0 0 1.7 3h14.6A2 2 0 0 0 21 17L13.7 4.4a2 2 0 0 0-3.4 0Z" /><path d="M12 9v4M12 17h.01" /></>,
    report: <><path d="M6 3h9l3 3v15H6z" /><path d="M15 3v4h4M9 12h6M9 16h6" /></>,
  }
  return <svg viewBox="0 0 24 24" aria-hidden="true">{paths[name]}</svg>
}

export default function AppShell({ activePage, onLogout, onToggleTheme, isDark, onNavigate, children }) {
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="sidebar-top">
          <BrandMark />
          <nav aria-label="Main navigation">
            <p className="nav-label">Workspace</p>
            {navigation.map((item) => (
              <button
                className={`nav-item ${activePage === item.id ? 'active' : ''}`}
                key={item.id}
                onClick={() => onNavigate(item.id)}
                type="button"
              >
                <NavIcon name={item.icon} />
                <span>{item.label}</span>
              </button>
            ))}
          </nav>
        </div>
        <button className="profile-card" onClick={onLogout} type="button">
          <div className="profile-avatar">ICT</div>
          <div>
            <strong>School ICT staff</strong>
            <span>Administrator</span>
          </div>
        </button>
      </aside>
      <main className="main-content">
        <header className="topbar">
          <button className="school-selector" type="button">
            <span className="selector-dot" />
            Secondary school workspace
            <span className="chevron">⌄</span>
          </button>
          <div className="top-actions"><button className="theme-switch" onClick={onToggleTheme} type="button">{isDark ? 'Light' : 'Dark'}</button><button className="help-button" type="button" aria-label="Help">?</button></div>
        </header>
        <section className="page-content">{children}</section>
      </main>
    </div>
  )
}
