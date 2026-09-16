import { useCallback, useEffect, useState } from 'react'
import { apiGet } from '../services/api'

function formatTime(iso) {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString('en-GB', {
    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
  })
}

export default function ComputersPage() {
  const [computers, setComputers] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const data = await apiGet('/endpoints')
      setComputers(Array.isArray(data) ? data : [])
    } catch (err) {
      if (err.status === 401) {
        window.location.hash = '/login'
        return
      }
      setError(err.message || 'Could not load computers.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  return (
    <div className="dashboard-page">
      <div className="dashboard-heading">
        <div>
          <p>School CyberWatch</p>
          <h1>Computers</h1>
          <span>School computers monitored by Wazuh agents</span>
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
            <p>Monitoring</p>
            <h2>Monitored endpoints</h2>
          </div>
        </div>
        <div className="alerts-table page-table">
          <div className="table-row table-head table-5">
            <span>Computer</span><span>IP address</span><span>Operating system</span><span>Agent status</span><span>Last seen</span>
          </div>
          {loading && computers.length === 0 ? (
            <div className="table-row table-5"><span>Loading computers…</span><span /><span /><span /><span /></div>
          ) : !error && computers.length === 0 ? (
            <div className="table-row table-5"><span className="empty-cell">No monitored computers found.</span><span /><span /><span /><span /></div>
          ) : (
            computers.map((computer) => (
              <div className="table-row table-5" key={computer.id}>
                <strong>{computer.name}</strong>
                <span>{computer.ip || '—'}</span>
                <span>{computer.os}</span>
                <span>
                  <b className={`status ${computer.status === 'Online' ? 'online' : 'offline'}`}>{computer.status}</b>
                </span>
                <span>{formatTime(computer.lastSeen)}</span>
              </div>
            ))
          )}
        </div>
      </section>
    </div>
  )
}
