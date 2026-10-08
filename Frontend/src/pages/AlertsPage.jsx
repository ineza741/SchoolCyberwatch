import { useCallback, useEffect, useState } from 'react'
import { apiGet } from '../services/api'
import AlertDetailModal from '../components/AlertDetailModal'
import { formatTime, typeLabel, SEVERITY_LEVELS, KNOWN_TYPES } from '../utils/format'

const TYPE_OPTIONS = [
  { value: '', label: 'All types' },
  ...KNOWN_TYPES.map((type) => ({ value: type, label: typeLabel(type) })),
]

/** Shared prefill payload for the incident workflow. */
function prefillIncident(alert) {
  sessionStorage.setItem('scw.prefillIncident', JSON.stringify({
    title: `${typeLabel(alert.type)} on ${alert.computer || 'school computer'}`,
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
  const [ruleId, setRuleId] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [search, setSearch] = useState('')
  const [selectedId, setSelectedId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      // All filtering happens backend-side on the Wazuh indexer - the
      // browser never downloads the full alert history.
      const params = new URLSearchParams()
      if (severity) params.set('severity', severity)
      if (type) params.set('type', type)
      if (ruleId) params.set('ruleId', ruleId.trim())
      if (from) params.set('from', new Date(from).toISOString())
      if (to) params.set('to', new Date(to).toISOString())
      if (search) params.set('search', search)
      params.set('limit', '200')
      const query = params.toString()
      const data = await apiGet(`/alerts${query ? `?${query}` : ''}`)
      setAlerts(Array.isArray(data) ? data : [])
    } catch (err) {
      if (err.status === 401) {
        window.location.hash = '/login'
        return
      }
      setError(err.message || 'Could not load security alerts.')
    } finally {
      setLoading(false)
    }
  }, [severity, type, ruleId, from, to, search])

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
              {SEVERITY_LEVELS.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
            <select value={type} onChange={(event) => setType(event.target.value)} aria-label="Filter by type">
              {TYPE_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>{option.label}</option>
              ))}
            </select>
            <input
              value={ruleId}
              onChange={(event) => setRuleId(event.target.value)}
              placeholder="Rule ID e.g. 100301"
              aria-label="Filter by rule id"
              className="filter-narrow"
            />
            <input
              type="datetime-local"
              value={from}
              onChange={(event) => setFrom(event.target.value)}
              aria-label="From date and time"
              title="From date and time"
            />
            <input
              type="datetime-local"
              value={to}
              onChange={(event) => setTo(event.target.value)}
              aria-label="To date and time"
              title="To date and time"
            />
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
            <span>Time</span><span>Computer</span><span>Alert</span><span>Type</span><span>Severity</span><span>Rule</span><span>Action</span>
          </div>
          {loading && alerts.length === 0 ? (
            <div className="table-row table-7"><span>Loading security alerts…</span><span /><span /><span /><span /><span /><span /></div>
          ) : !error && alerts.length === 0 ? (
            <div className="table-row table-7"><span className="empty-cell">No security alerts found.</span><span /><span /><span /><span /><span /><span /></div>
          ) : (
            alerts.map((alert) => (
              <div
                className="table-row table-7 clickable"
                key={alert.id}
                onClick={() => setSelectedId(alert.id)}
                title="View alert details"
              >
                <span>{formatTime(alert.timestamp)}</span>
                <strong>{alert.computer || '—'}</strong>
                <span>
                  {alert.title}
                  {alert.description ? <small className="alert-desc">{alert.description}</small> : null}
                </span>
                <span><span className="type-chip">{typeLabel(alert.type)}</span></span>
                <span><b className={`severity ${(alert.severity || '').toLowerCase()}`}>{alert.severity || '—'}</b></span>
                <span>{alert.ruleId || '—'}</span>
                <span>
                  <button
                    type="button"
                    className="row-action"
                    title="Turn this alert into an incident"
                    onClick={(event) => {
                      event.stopPropagation()
                      prefillIncident(alert)
                    }}
                  >
                    Create incident
                  </button>
                </span>
              </div>
            ))
          )}
        </div>
        <p className="table-footnote">Showing up to 200 events. Use the filters to narrow the feed.</p>
      </section>

      {selectedId ? (
        <AlertDetailModal
          alertId={selectedId}
          onClose={() => setSelectedId(null)}
          footerExtra={
            <button type="button" onClick={() => prefillIncident(alerts.find((a) => a.id === selectedId) || {})}>
              Create incident from this alert
            </button>
          }
        />
      ) : null}
    </div>
  )
}
