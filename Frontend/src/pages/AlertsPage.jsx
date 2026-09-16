import { useCallback, useEffect, useState } from 'react'
import { apiGet } from '../services/api'

const SEVERITY_OPTIONS = ['', 'Critical', 'High', 'Medium', 'Low']
const TYPE_OPTIONS = [
  { value: '', label: 'All types' },
  { value: 'FAILED_LOGIN', label: 'Failed login' },
  { value: 'BRUTE_FORCE', label: 'Brute force' },
  { value: 'FILE_MODIFIED', label: 'File modified' },
  { value: 'FILE_DELETED', label: 'File deleted' },
]

function formatTime(iso) {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString('en-GB', {
    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
  })
}

/**
 * Hands the chosen alert to the Incidents page: stores it briefly and
 * navigates there; IncidentsPage opens its form pre-filled from it.
 */
function createIncidentFromAlert(alert) {
  sessionStorage.setItem('scw.prefillIncident', JSON.stringify({
    title: `${alert.title} on ${alert.computer}`,
    description: alert.description || '',
    severity: alert.severity || 'Medium',
    sourceAlertId: alert.id || '',
    computer: alert.computer || '',
  }))
  window.location.hash = '/incidents'
}

export default function AlertsPage() {
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [severity, setSeverity] = useState('')
  const [type, setType] = useState('')
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const params = new URLSearchParams()
      if (severity) params.set('severity', severity)
      if (type) params.set('type', type)
      if (search) params.set('search', search)
      const query = params.toString()
      const data = await apiGet(`/alerts${query ? `?${query}` : ''}`)
      setAlerts(Array.isArray(data) ? data : [])
    } catch (err) {
      if (err.status === 401) {
        window.location.hash = '/login'
        return
      }
      setError(err.message || 'Could not load alerts.')
    } finally {
      setLoading(false)
    }
  }, [severity, type, search])

  useEffect(() => { load() }, [load])

  return (
    <div className="dashboard-page">
      <div className="dashboard-heading">
        <div>
          <p>School CyberWatch</p>
          <h1>Security alerts</h1>
          <span>Live events from the Wazuh monitoring service</span>
        </div>
        <button type="button" onClick={load}>Refresh</button>
      </div>

      {error ? (
        <section className="alerts-panel" role="alert" style={{ marginTop: 30 }}>
          <p className="login-error">{error}</p>
        </section>
      ) : null}

      <section className="alerts-panel" style={{ marginTop: 30 }}>
        <div className="panel-heading">
          <div>
            <p>Event feed</p>
            <h2>Security events</h2>
          </div>
          <div className="filters-row">
            <select value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Filter by severity">
              <option value="">All severities</option>
              {SEVERITY_OPTIONS.filter(Boolean).map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
            <select value={type} onChange={(event) => setType(event.target.value)} aria-label="Filter by type">
              {TYPE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search computer, rule, text…"
              aria-label="Search alerts"
            />
          </div>
        </div>

        <div className="alerts-table page-table">
          <div className="table-row table-head table-7">
            <span>Time</span><span>Computer</span><span>Alert</span><span>Severity</span><span>Rule</span><span>Status</span><span>Action</span>
          </div>
          {loading && alerts.length === 0 ? (
            <div className="table-row table-7"><span>Loading alerts…</span><span /><span /><span /><span /><span /><span /></div>
          ) : !error && alerts.length === 0 ? (
            <div className="table-row table-7"><span className="empty-cell">No security alerts found.</span><span /><span /><span /><span /><span /><span /></div>
          ) : (
            alerts.map((alert) => (
              <div className="table-row table-7" key={alert.id}>
                <span>{formatTime(alert.timestamp)}</span>
                <strong>{alert.computer}</strong>
                <span>
                  {alert.title}
                  {alert.description ? <small className="alert-desc">{alert.description}</small> : null}
                  {alert.ruleId ? <small className="alert-rule">Rule {alert.ruleId}</small> : null}
                </span>
                <span><b className={`severity ${(alert.severity || '').toLowerCase()}`}>{alert.severity}</b></span>
                <span>{alert.ruleId}</span>
                <span><b className={`status ${(alert.status || '').toLowerCase()}`}>{alert.status}</b></span>
                <span>
                  <button
                    type="button"
                    className="row-action"
                    title="Turn this alert into an incident"
                    onClick={() => createIncidentFromAlert(alert)}
                  >
                    Create incident
                  </button>
                </span>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  )
}
