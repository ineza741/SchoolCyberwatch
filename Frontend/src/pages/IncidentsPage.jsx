import { useCallback, useEffect, useState } from 'react'
import { apiGet, apiPost } from '../services/api'

const STATUS_OPTIONS = ['OPEN', 'INVESTIGATING', 'RESOLVED']
const SEVERITY_OPTIONS = ['Low', 'Medium', 'High', 'Critical']
const PREFILL_KEY = 'scw.prefillIncident'

function formatTime(iso) {
  if (!iso) return '—'
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString('en-GB', {
    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
  })
}

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({
    title: '', description: '', severity: 'Medium', sourceAlertId: '', computer: '',
  })
  const [formError, setFormError] = useState('')
  const [creating, setCreating] = useState(false)
  const [noteDrafts, setNoteDrafts] = useState({})
  const [busyId, setBusyId] = useState(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const data = await apiGet(`/incidents${statusFilter ? `?status=${statusFilter}` : ''}`)
      setIncidents(Array.isArray(data) ? data : [])
    } catch (err) {
      if (err.status === 401) {
        window.location.hash = '/login'
        return
      }
      setError(err.message || 'Could not load incidents.')
    } finally {
      setLoading(false)
    }
  }, [statusFilter])

  useEffect(() => { load() }, [load])

  // Open the form pre-filled when arriving from an alert's "Create incident" button.
  useEffect(() => {
    const raw = sessionStorage.getItem(PREFILL_KEY)
    if (!raw) return
    sessionStorage.removeItem(PREFILL_KEY)
    try {
      const prefill = JSON.parse(raw)
      setForm((current) => ({
        ...current,
        title: prefill.title || '',
        description: prefill.description || '',
        severity: SEVERITY_OPTIONS.includes(prefill.severity) ? prefill.severity : 'Medium',
        sourceAlertId: prefill.sourceAlertId || '',
        computer: prefill.computer || '',
      }))
      setShowForm(true)
    } catch {
      // Ignore malformed prefill data.
    }
  }, [])

  async function handleCreate(event) {
    event.preventDefault()
    setFormError('')
    if (!form.title.trim()) {
      setFormError('Please give the incident a title.')
      return
    }
    setCreating(true)
    try {
      await apiPost('/incidents', form)
      setForm({ title: '', description: '', severity: 'Medium', sourceAlertId: '', computer: '' })
      setShowForm(false)
      await load()
    } catch (err) {
      setFormError(err.message)
    } finally {
      setCreating(false)
    }
  }

  async function changeStatus(incident, status) {
    setBusyId(incident.id)
    try {
      await apiPost(`/incidents/${incident.id}/status`, { status })
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusyId(null)
    }
  }

  async function addNote(incident) {
    const note = (noteDrafts[incident.id] || '').trim()
    if (!note) return
    setBusyId(incident.id)
    try {
      await apiPost(`/incidents/${incident.id}/notes`, { note })
      setNoteDrafts((drafts) => ({ ...drafts, [incident.id]: '' }))
      await load()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusyId(null)
    }
  }

  function updateNoteDraft(id, text) {
    setNoteDrafts((drafts) => ({ ...drafts, [id]: text }))
  }

  return (
    <div className="dashboard-page">
      <div className="dashboard-heading">
        <div>
          <p>School CyberWatch</p>
          <h1>Incidents</h1>
          <span>Track and resolve security incidents</span>
        </div>
        <button type="button" onClick={() => setShowForm((open) => !open)}>
          {showForm ? 'Close form' : '+ New incident'}
        </button>
      </div>

      {error ? (
        <section className="alerts-panel" role="alert" style={{ marginTop: 30 }}>
          <p className="login-error">{error}</p>
        </section>
      ) : null}

      {showForm ? (
        <section className="alerts-panel" style={{ marginTop: 30 }}>
          <div className="panel-heading"><div><p>Create</p><h2>New incident</h2></div></div>
          <form className="incident-form" onSubmit={handleCreate}>
            <label>
              Title *
              <input
                value={form.title}
                onChange={(event) => setForm({ ...form, title: event.target.value })}
                placeholder="e.g. Brute-force attack on Examination-PC"
                required
              />
            </label>
            <label>
              Description
              <textarea
                rows={3}
                value={form.description}
                onChange={(event) => setForm({ ...form, description: event.target.value })}
                placeholder="What happened, what was affected…"
              />
            </label>
            <div className="form-grid">
              <label>
                Severity
                <select value={form.severity} onChange={(event) => setForm({ ...form, severity: event.target.value })}>
                  {SEVERITY_OPTIONS.map((option) => <option key={option} value={option}>{option}</option>)}
                </select>
              </label>
              <label>
                Computer
                <input
                  value={form.computer}
                  onChange={(event) => setForm({ ...form, computer: event.target.value })}
                  placeholder="e.g. WIN-HUR37I74T1G"
                />
              </label>
              <label>
                Source alert ID (optional)
                <input
                  value={form.sourceAlertId}
                  onChange={(event) => setForm({ ...form, sourceAlertId: event.target.value })}
                  placeholder="Wazuh alert id"
                />
              </label>
            </div>
            {formError ? <p className="login-error" role="alert">{formError}</p> : null}
            <button type="submit" disabled={creating}>
              {creating ? 'Creating…' : 'Create incident'}
            </button>
          </form>
        </section>
      ) : null}

      <section className="alerts-panel" style={{ marginTop: 30 }}>
        <div className="panel-heading">
          <div>
            <p>Workflow</p>
            <h2>Incident register</h2>
          </div>
          <div className="filters-row">
            <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)} aria-label="Filter by status">
              <option value="">All statuses</option>
              {STATUS_OPTIONS.map((option) => <option key={option} value={option}>{option}</option>)}
            </select>
            <button type="button" onClick={load}>Refresh</button>
          </div>
        </div>

        {loading && incidents.length === 0 ? (
          <p className="empty-cell" style={{ marginTop: 20 }}>Loading incidents…</p>
        ) : !error && incidents.length === 0 ? (
          <p className="empty-cell" style={{ marginTop: 20 }}>No incidents found. Create one from an important alert.</p>
        ) : (
          <div className="incident-list">
            {incidents.map((incident) => (
              <article className="incident-card" key={incident.id}>
                <header>
                  <div>
                    <strong>{incident.title}</strong>
                    <small>
                      {formatTime(incident.createdAt)} · {incident.computer || 'Unknown computer'}
                      {incident.sourceAlertId ? ` · alert ${incident.sourceAlertId}` : ''}
                    </small>
                  </div>
                  <div className="incident-badges">
                    <b className={`severity ${(incident.severity || '').toLowerCase()}`}>{incident.severity}</b>
                    <b className={`status ${(incident.status || '').toLowerCase()}`}>{incident.status}</b>
                  </div>
                </header>
                {incident.description ? <p>{incident.description}</p> : null}

                <div className="incident-actions">
                  {STATUS_OPTIONS.filter((status) => status !== incident.status).map((status) => (
                    <button
                      key={status}
                      type="button"
                      disabled={busyId === incident.id}
                      onClick={() => changeStatus(incident, status)}
                    >
                      Mark {status.toLowerCase()}
                    </button>
                  ))}
                </div>

                {incident.notes && incident.notes.length > 0 ? (
                  <ul className="incident-notes">
                    {incident.notes.map((note) => (
                      <li key={note.id}>
                        <span>{note.note}</span>
                        <small>{note.author || 'ICT administrator'} · {formatTime(note.createdAt)}</small>
                      </li>
                    ))}
                  </ul>
                ) : null}

                <div className="note-add">
                  <input
                    value={noteDrafts[incident.id] || ''}
                    onChange={(event) => updateNoteDraft(incident.id, event.target.value)}
                    placeholder="Add a note…"
                    onKeyDown={(event) => {
                      if (event.key === 'Enter') addNote(incident)
                    }}
                  />
                  <button type="button" disabled={busyId === incident.id} onClick={() => addNote(incident)}>Add</button>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
