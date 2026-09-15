import { useState } from 'react'
import AppShell from './components/AppShell'
import PlaceholderPage from './pages/PlaceholderPage'

const pages = {
  dashboard: {
    eyebrow: 'School CyberWatch',
    title: 'Security overview',
    description: 'Your school security summary will appear here once the dashboard service is connected.',
  },
  computers: {
    eyebrow: 'Monitoring',
    title: 'Computers',
    description: 'Connected computers and their Wazuh agent status will appear here.',
  },
  alerts: {
    eyebrow: 'Detection',
    title: 'Security alerts',
    description: 'Alerts from the backend will appear here with simple filters and clear severity labels.',
  },
  incidents: {
    eyebrow: 'Response',
    title: 'Incidents',
    description: 'Your incident list and investigation workflow will appear here.',
  },
  reports: {
    eyebrow: 'Reporting',
    title: 'Reports',
    description: 'Generate and download security reports from this page once reporting is connected.',
  },
}

export default function App() {
  const [activePage, setActivePage] = useState('dashboard')

  return (
    <AppShell activePage={activePage} onNavigate={setActivePage}>
      <PlaceholderPage {...pages[activePage]} />
    </AppShell>
  )
}
