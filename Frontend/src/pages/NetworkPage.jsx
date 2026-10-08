import { useCallback, useEffect, useState } from 'react'
import { apiGet } from '../services/api'
import { formatNumber, formatTime, typeLabel, orDash, protocolLabel, SEVERITY_LEVELS } from '../utils/format'

/** Shared prefill payload for the incident workflow. */
function prefillIncident(event) {
  sessionStorage.setItem('scw.prefillIncident', JSON.stringify({
    title: `${typeLabel(event.type)} on ${event.computer || 'school computer'}`,
    description: event.description || '',
    severity: event.severity || 'Medium',
    sourceAlertId: event.id || '',
    computer: event.computer || '',
  }))
  window.location.hash = '/incidents'
}

export default function NetworkPage() {
  const [events, setEvents] = useState([])
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [eventType, setEventType] = useState('')
  const [severity, setSeverity] = useState('')
  const [computer, setComputer] = useState('')
  const [protocol, setProtocol] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      // Backend applies the 72-hour window and caps the page size; the
      // browser never loads the full network history (100k+ events). The
      // summary cards are answered by exact Indexer counts instead of by
      // counting this bounded page.
      const [eventsData, summaryData] = await Promise.all([
        apiGet('/network/events?limit=200'),
        apiGet('/network/summary'),
      ])
      setEvents(Array.isArray(eventsData) ? eventsData : [])
      setSummary(summaryData || null)
    } catch (err) {
      if (err.status === 401) {
        window.location.hash = '/login'
        return
      }
      setError(err.message || 'Could not load network events.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const computers = Array.from(new Set(events.map((event) => event.computer).filter(Boolean)))
  // Protocol options come from the loaded page (the backend sends IP protocol
  // numbers), so the filter can always match real values.
  const protocols = Array.from(new Set(events.map((event) => event.protocol).filter((value) => value !== null && value !== undefined && value !== '')))
    .sort((a, b) => Number(a) - Number(b))

  // Client-side narrowing of the already-limited backend page only.
  const filtered = events.filter((event) => {
    if (eventType && event.type !== eventType) return false
    if (severity && event.severity !== severity) return false
    if (computer && event.computer !== computer) return false
    if (protocol && event.protocol !== protocol) return false
    return true
  })

  const scans = events.filter((event) => event.type === 'NETWORK_SCAN').length

  // The cards quote exact Indexer counts; label them with the window the
  // backend actually used instead of assuming one.
  const windowHours = summary && summary.windowHours ? summary.windowHours : 72
  const scopeNote = summary && summary.windowStart
    ? `Exact count for rules 100300 + 100301 from ${summary.windowStart} to ${summary.windowEnd}`
    : 'Exact count for rules 100300 + 100301 over the rolling window'

  return (
    <div className="dashboard-page">
      <div className="dashboard-heading">
        <div>
          <p>School CyberWatch</p>
          <h1>Network monitoring</h1>
          <span>Inbound connections (rule 100300) and possible scans (rule 100301)</span>
        </div>
        <button type="button" onClick={load}>Refresh</button>
      </div>

      {error ? (
        <section className="alerts-panel" role="alert" style={{ marginTop: 30 }}>
          <p className="login-error">{error}</p>
        </section>
      ) : null}

      <section className="summary-grid network-grid">
        <article className="summary-card neutral">
          <span title={scopeNote}>Total network events ({windowHours}h)</span>
          <strong title={summary ? String(summary.totalEvents) : ''}>
            {summary ? formatNumber(summary.totalEvents) : '--'}
          </strong>
          <i />
        </article>
        <article className="summary-card critical">
          <span title={scopeNote}>High-severity network alerts ({windowHours}h)</span>
          <strong title={summary ? String(summary.highSeverity) : ''}>
            {summary ? formatNumber(summary.highSeverity) : '--'}
          </strong>
          <i />
        </article>
        <article className="summary-card warning">
          <span>Possible scans on this page</span>
          <strong>{formatNumber(scans)}</strong>
          <i />
        </article>
      </section>

      <section className="alerts-panel">
        <div className="panel-heading">
          <div>
            <p>Event feed</p>
            <h2>Network events</h2>
          </div>
          <div className="filters-row">
            <select value={eventType} onChange={(event) => setEventType(event.target.value)} aria-label="Filter by event type">
              <option value="">All events</option>
              <option value="NETWORK_CONNECTION">Network Connection (100300)</option>
              <option value="NETWORK_SCAN">Possible Network Scan (100301)</option>
              <option value="BRUTE_FORCE">Brute Force (100200)</option>
              <option value="FAILED_LOGIN">Failed Login (60122)</option>
            </select>
            <select value={severity} onChange={(event) => setSeverity(event.target.value)} aria-label="Filter by severity">
              <option value="">All severities</option>
              {SEVERITY_LEVELS.map((option) => (
                <option key={option} value={option}>{option}</option>
              ))}
            </select>
            <select value={computer} onChange={(event) => setComputer(event.target.value)} aria-label="Filter by endpoint">
              <option value="">All endpoints</option>
              {computers.map((name) => (
                <option key={name} value={name}>{name}</option>
              ))}
            </select>
            <select value={protocol} onChange={(event) => setProtocol(event.target.value)} aria-label="Filter by protocol">
              <option value="">All protocols</option>
              {protocols.map((value) => (
                <option key={value} value={value}>{protocolLabel(value)}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="alerts-table page-table">
          <div className="table-row table-head table-8">
            <span>Time</span><span>Computer</span><span>Source IP</span><span>Destination IP</span><span title="Source port / destination port">Ports</span><span>Protocol</span><span>Event</span><span>Severity</span>
          </div>
          {loading && events.length === 0 ? (
            <div className="table-row table-8"><span>Loading network events…</span><span /><span /><span /><span /><span /><span /><span /></div>
          ) : !error && filtered.length === 0 ? (
            <div className="table-row table-8"><span className="empty-cell">No network events found.</span><span /><span /><span /><span /><span /><span /><span /></div>
          ) : (
            filtered.map((event) => {
              const isScan = event.type === 'NETWORK_SCAN'
              return (
                <div className={`table-row table-8 ${isScan ? 'scan-row' : ''}`} key={event.id}>
                  <span>{formatTime(event.timestamp)}</span>
                  <strong>{event.computer || '—'}</strong>
                  <span className="mono">{event.sourceIp || 'N/A'}</span>
                  <span className="mono">{event.destinationIp || 'N/A'}</span>
                  <span className="mono">{orDash(event.sourcePort)} / {orDash(event.destinationPort)}</span>
                  <span>{protocolLabel(event.protocol)}</span>
                  <span>
                    {isScan ? (
                      <span className="type-chip scan">⚠ {event.title}</span>
                    ) : (
                      <span className="type-chip">{event.title}</span>
                    )}
                    {event.description ? <small className="alert-desc">{event.description}</small> : null}
                    {event.ruleId ? <small className="alert-rule">Rule {event.ruleId}</small> : null}
                  </span>
                  <span>
                    <b className={`severity ${(event.severity || '').toLowerCase()}`}>{event.severity || '—'}</b>
                    {(event.severity === 'High' || event.severity === 'Critical') ? (
                      <button
                        type="button"
                        className="row-action"
                        title="Turn this event into an incident"
                        onClick={() => prefillIncident(event)}
                      >
                        Incident
                      </button>
                    ) : null}
                  </span>
                </div>
              )
            })
          )}
        </div>
        <p className="table-footnote">
          Summary cards are exact Indexer counts for rules 100300 and 100301 over the last {windowHours} hours.
          The feed below shows up to 200 of the most recent events from that same window. Scans are highlighted.
        </p>
      </section>
    </div>
  )
}
