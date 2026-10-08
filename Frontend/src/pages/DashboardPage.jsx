import { useEffect, useState } from 'react'
import { apiGet } from '../services/api'
import { formatNumber, formatTime, typeLabel, SEVERITY_LEVELS, KNOWN_TYPES } from '../utils/format'

function todayLabel() {
  return new Date().toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long' })
}

/** Horizontal bar built from real counts only. */
function Bar({ label, value, total, tone }) {
  const percent = total > 0 ? Math.max((value / total) * 100, 1.5) : 0
  return (
    <div className="chart-row" key={label}>
      <span className="chart-label">{label}</span>
      <div className="chart-track">
        <div className={`chart-fill ${tone || ''}`} style={{ width: `${percent}%` }} />
      </div>
      <span className="chart-value">{formatNumber(value)}</span>
    </div>
  )
}

/** Alerts-per-day line built from the real overTime series. */
function OverTimeChart({ overTime }) {
  const days = Object.entries(overTime || {})
  if (days.length === 0) return null
  const max = Math.max(...days.map(([, value]) => value), 1)
  return (
    <div className="overtime-chart" role="img" aria-label="Alerts per day">
      {days.map(([day, value]) => (
        <div className="overtime-day" key={day} title={`${day}: ${formatNumber(value)} alerts`}>
          <div className="overtime-bar" style={{ height: `${Math.max((value / max) * 100, 2)}%` }} />
          <span className="overtime-label">{day.slice(8)}/{day.slice(5, 7)}</span>
        </div>
      ))}
    </div>
  )
}

export default function DashboardPage() {
  const [summary, setSummary] = useState([])
  const [stats, setStats] = useState(null)
  const [recent, setRecent] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      setError('')
      try {
        // Summary cards + 30-day statistics, all computed from real Wazuh data.
        const [summaryData, statsData] = await Promise.all([
          apiGet('/dashboard/summary'),
          apiGet('/dashboard/stats?days=30'),
        ])
        if (cancelled) return
        setSummary(Array.isArray(summaryData) ? summaryData : [])
        setStats(statsData || null)
        setRecent(Array.isArray(statsData?.recentAlerts) ? statsData.recentAlerts : [])
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

  const severityRows = stats
    ? SEVERITY_LEVELS.map((level) => [level, stats.bySeverity?.[level] || 0])
    : []
  const severityTotal = severityRows.reduce((sum, [, value]) => sum + value, 0)

  const typeRows = stats
    ? KNOWN_TYPES.map((type) => [typeLabel(type), stats.byType?.[type] || 0])
    : []
  const typeTotal = typeRows.reduce((sum, [, value]) => sum + value, 0)

  return (
    <div className="dashboard-page">
      <div className="dashboard-heading">
        <div>
          <p>School CyberWatch</p>
          <h1>Security overview</h1>
          <span>{todayLabel()}{stats ? ` · last ${stats.windowDays} days` : ''}</span>
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
          ? Array.from({ length: 6 }).map((_, index) => (
            <article className="summary-card" key={`skeleton-${index}`}>
              <span>…</span>
              <strong>--</strong>
              <i />
            </article>
          ))
          : summary.map((item) => (
            <article className={`summary-card ${item.tone || 'neutral'}`} key={item.label}>
              <span>{item.label}</span>
              <strong title={item.value}>{formatNumber(item.value)}</strong>
              <i />
            </article>
          ))}
      </section>

      <div className="charts-grid">
        <section className="alerts-panel">
          <div className="panel-heading">
            <div>
              <p>Severity breakdown</p>
              <h2>Alerts by severity</h2>
            </div>
          </div>
          <div className="chart-body">
            {loading && !stats ? (
              <p className="empty-cell">Loading statistics…</p>
            ) : severityTotal === 0 ? (
              <p className="empty-cell">No alerts recorded in this period.</p>
            ) : (
              severityRows.map(([label, value]) => (
                <Bar key={label} label={label} value={value} total={severityTotal} tone={label.toLowerCase()} />
              ))
            )}
          </div>
        </section>

        <section className="alerts-panel">
          <div className="panel-heading">
            <div>
              <p>Detection types</p>
              <h2>Alerts by type</h2>
            </div>
          </div>
          <div className="chart-body">
            {loading && !stats ? (
              <p className="empty-cell">Loading statistics…</p>
            ) : typeTotal === 0 ? (
              <p className="empty-cell">No alerts recorded in this period.</p>
            ) : (
              typeRows.map(([label, value]) => (
                <Bar key={label} label={label} value={value} total={typeTotal} tone="violet" />
              ))
            )}
          </div>
        </section>
      </div>

      <section className="alerts-panel" style={{ marginTop: 22 }}>
        <div className="panel-heading">
          <div>
            <p>Last {stats?.windowDays || 7} days</p>
            <h2>Alerts over time</h2>
          </div>
          <span className="panel-total">{formatNumber(stats?.totalAlerts)} total alerts</span>
        </div>
        {loading && !stats ? (
          <p className="empty-cell" style={{ marginTop: 20 }}>Loading statistics…</p>
        ) : (
          <OverTimeChart overTime={stats?.overTime} />
        )}
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
            <span>Alert</span><span>Device</span><span>Severity</span><span>Time</span><span>Rule</span>
          </div>
          {loading && recent.length === 0 ? (
            <div className="table-row"><span>Loading alerts…</span><span /><span /><span /><span /></div>
          ) : !error && recent.length === 0 ? (
            <div className="table-row"><span className="empty-cell">No security alerts found.</span><span /><span /><span /><span /></div>
          ) : (
            recent.slice(0, 8).map((alert) => (
              <div className="table-row" key={alert.id}>
                <strong>{alert.title || typeLabel(alert.type)}</strong>
                <span>{alert.computer || '—'}</span>
                <span><b className={`severity ${(alert.severity || '').toLowerCase()}`}>{alert.severity || '—'}</b></span>
                <span>{formatTime(alert.timestamp)}</span>
                <span>{alert.ruleId || '—'}</span>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  )
}
