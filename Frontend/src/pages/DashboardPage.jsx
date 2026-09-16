import { useEffect, useState } from 'react'
import { apiGet } from '../services/api'

function todayLabel() {
  return new Date().toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long' })
}

export default function DashboardPage() {
  const [summary, setSummary] = useState([])
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      setError('')
      try {
        const [summaryData, alertsData] = await Promise.all([
          apiGet('/dashboard/summary'),
          apiGet('/dashboard/alerts'),
        ])
        if (cancelled) return
        setSummary(Array.isArray(summaryData) ? summaryData : [])
        setAlerts(Array.isArray(alertsData) ? alertsData : [])
      } catch (err) {
        if (cancelled) return
        if (err.status === 401) {
          window.location.hash = '/login'
          return
        }
        setError(err.message || 'Could not load security data.')
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [])

  return (
    <div className="dashboard-page">
      <div className="dashboard-heading">
        <div>
          <p>School CyberWatch</p>
          <h1>Security overview</h1>
          <span>{todayLabel()}</span>
        </div>
        <button type="button" onClick={() => { window.location.hash = '/alerts' }}>View all alerts</button>
      </div>

      {error ? (
        <section className="alerts-panel" role="alert" style={{ marginTop: 30 }}>
          <p className="login-error">{error}</p>
        </section>
      ) : null}

      <section className="summary-grid">
        {loading && summary.length === 0
          ? Array.from({ length: 5 }).map((_, index) => (
            <article className="summary-card" key={`skeleton-${index}`}>
              <span>…</span>
              <strong>--</strong>
              <i />
            </article>
          ))
          : summary.map((item) => (
            <article className={`summary-card ${item.tone || 'neutral'}`} key={item.label}>
              <span>{item.label}</span>
              <strong>{item.value}</strong>
              <i />
            </article>
          ))}
      </section>

      <section className="alerts-panel">
        <div className="panel-heading">
          <div>
            <p>Latest activity</p>
            <h2>Recent security alerts</h2>
          </div>
          <button type="button" onClick={() => { window.location.hash = '/alerts' }}>Filter alerts</button>
        </div>
        <div className="alerts-table">
          <div className="table-row table-head">
            <span>Alert</span><span>Device</span><span>Severity</span><span>Time</span><span>Status</span>
          </div>
          {loading && alerts.length === 0 ? (
            <div className="table-row"><span>Loading alerts…</span><span /><span /><span /><span /></div>
          ) : error ? (
            <div className="table-row"><span>Alerts unavailable.</span><span /><span /><span /><span /></div>
          ) : alerts.length === 0 ? (
            <div className="table-row"><span>No security alerts found.</span><span /><span /><span /><span /></div>
          ) : (
            alerts.map((alert) => (
              <div className="table-row" key={alert.id}>
                <strong>{alert.name}</strong>
                <span>{alert.device}</span>
                <span><b className={`severity ${(alert.severity || '').toLowerCase()}`}>{alert.severity}</b></span>
                <span>{alert.time}</span>
                <span><b className={`status ${(alert.status || '').toLowerCase()}`}>{alert.status}</b></span>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  )
}
