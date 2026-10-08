import { useEffect, useState } from 'react'
import { apiGet } from '../services/api'
import { formatTimeFull, typeLabel, protocolLabel } from '../utils/format'

/** Detail fields grouped the way the administrator reads them. */
function DetailSection({ title, rows }) {
  const visible = rows.filter(([, value]) => value !== null && value !== undefined && String(value).trim() !== '')
  if (visible.length === 0) return null
  return (
    <div className="detail-section">
      <h3>{title}</h3>
      <dl>
        {visible.map(([label, value]) => (
          <div className="detail-row" key={label}>
            <dt>{label}</dt>
            <dd>{String(value)}</dd>
          </div>
        ))}
      </dl>
    </div>
  )
}

/**
 * Alert detail dialog backed by the verified GET /api/alerts/{id} endpoint.
 * Optional Wazuh fields (username, file path, threat, network addresses)
 * simply disappear when the backend did not provide them - never "null".
 */
export default function AlertDetailModal({ alertId, onClose, footerExtra }) {
  const [alert, setAlert] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    async function load() {
      setLoading(true)
      setError('')
      try {
        const data = await apiGet(`/alerts/${encodeURIComponent(alertId)}`)
        if (!cancelled) setAlert(data)
      } catch (err) {
        if (!cancelled) setError(err.status === 404 ? 'This alert no longer exists.' : err.message)
      } finally {
        if (!cancelled) setLoading(false)
      }
    }
    load()
    return () => { cancelled = true }
  }, [alertId])

  useEffect(() => {
    const onKey = (event) => { if (event.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div className="modal-card" role="dialog" aria-modal="true" aria-label="Alert details" onClick={(event) => event.stopPropagation()}>
        <header className="modal-head">
          <div>
            <p>Security alert</p>
            <h2>{loading ? 'Loading alert…' : alert ? typeLabel(alert.type) : 'Alert unavailable'}</h2>
          </div>
          <button className="modal-close" type="button" onClick={onClose} aria-label="Close">×</button>
        </header>

        {loading ? (
          <p className="empty-cell">Loading alert details…</p>
        ) : error ? (
          <p className="login-error" role="alert">{error}</p>
        ) : alert ? (
          <div className="modal-body">
            <div className="modal-badges">
              <b className={`severity ${(alert.severity || '').toLowerCase()}`}>{alert.severity || 'Unknown'}</b>
              <b className={`status ${(alert.status || '').toLowerCase()}`}>{alert.status || 'NEW'}</b>
              {alert.ruleId ? <span className="rule-chip">Rule {alert.ruleId}</span> : null}
            </div>
            <p className="modal-description">{alert.description || 'No description provided for this event.'}</p>

            <DetailSection title="Event" rows={[
              ['Timestamp', formatTimeFull(alert.timestamp)],
              ['Event type', typeLabel(alert.type)],
              ['Rule ID', alert.ruleId],
              ['Rule level', alert.ruleLevel ? `${alert.ruleLevel} of 15` : null],
            ]} />

            <DetailSection title="Computer" rows={[
              ['Computer name', alert.computer],
              ['Agent ID', alert.agentId],
              ['Agent IP', alert.agentIp],
            ]} />

            <DetailSection title="Authentication" rows={[
              ['Username', alert.username],
            ]} />

            <DetailSection title="File security" rows={[
              ['File path', alert.filePath],
            ]} />

            <DetailSection title="Malware" rows={[
              ['Threat name', alert.threat],
            ]} />

            <DetailSection title="Network" rows={[
              ['Source IP', alert.sourceIp],
              ['Source port', alert.sourcePort],
              ['Destination IP', alert.destinationIp],
              ['Destination port', alert.destinationPort],
              ['Protocol', alert.protocol ? protocolLabel(alert.protocol) : null],
            ]} />

            <div className="modal-actions">
              {footerExtra || null}
            </div>
          </div>
        ) : null}
      </div>
    </div>
  )
}
