import { useState } from 'react'
import { API_BASE_URL } from '../config/api'
import { getAuthHeader } from '../services/auth'

export default function ReportsPage() {
  const [days, setDays] = useState('30')
  const [busy, setBusy] = useState(false)
  const [mailBusy, setMailBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [error, setError] = useState('')

  async function downloadReport() {
    setBusy(true)
    setError('')
    setMessage('')
    try {
      const response = await fetch(`${API_BASE_URL}/reports/security-report.pdf?days=${days}`, {
        headers: getAuthHeader(),
      })
      if (response.status === 401) {
        window.location.hash = '/login'
        return
      }
      if (!response.ok) {
        const data = await response.json().catch(() => null)
        throw new Error((data && (data.error || data.message)) || `Report failed (HTTP ${response.status})`)
      }
      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `school-cyberwatch-report-${new Date().toISOString().slice(0, 10)}.pdf`
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
      setMessage('Report generated and downloaded.')
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function sendTestEmail() {
    setMailBusy(true)
    setError('')
    setMessage('')
    try {
      const response = await fetch(`${API_BASE_URL}/notifications/test`, {
        method: 'POST',
        headers: { ...getAuthHeader() },
      })
      const data = await response.json().catch(() => ({}))
      if (response.status === 401) {
        window.location.hash = '/login'
        return
      }
      if (!response.ok) {
        throw new Error(data.error || data.message || `Request failed (HTTP ${response.status})`)
      }
      setMessage(data.message || 'Test email sent.')
    } catch (err) {
      setError(err.message)
    } finally {
      setMailBusy(false)
    }
  }

  return (
    <div className="dashboard-page">
      <div className="dashboard-heading">
        <div>
          <p>School CyberWatch</p>
          <h1>Reports</h1>
          <span>Generate PDF security reports for your school</span>
        </div>
      </div>

      {error ? <p className="login-error" role="alert" style={{ marginTop: 26 }}>{error}</p> : null}
      {message ? <p className="report-success" role="status" style={{ marginTop: 26 }}>{message}</p> : null}

      <section className="alerts-panel" style={{ marginTop: 30 }}>
        <div className="panel-heading">
          <div>
            <p>Export</p>
            <h2>Security report (PDF)</h2>
          </div>
        </div>
        <div className="report-controls">
          <label>
            Reporting period
            <select value={days} onChange={(event) => setDays(event.target.value)}>
              <option value="7">Last 7 days</option>
              <option value="30">Last 30 days</option>
              <option value="90">Last 90 days</option>
            </select>
          </label>
          <button type="button" onClick={downloadReport} disabled={busy}>
            {busy ? 'Generating…' : 'Generate & download PDF'}
          </button>
        </div>
        <p className="report-note">
          The report includes monitored computers, alert totals per type (failed logins,
          brute force, file integrity), severity breakdown, incident counts and basic
          security recommendations. It needs the monitoring service (Wazuh) to be online.
        </p>
      </section>

      <section className="alerts-panel" style={{ marginTop: 22 }}>
        <div className="panel-heading">
          <div>
            <p>Notifications</p>
            <h2>Email alerts</h2>
          </div>
        </div>
        <p className="report-note">
          High and critical alerts (such as brute-force attacks, rule 100200) automatically
          send an email to the ICT administrator. Use the button below to verify the SMTP
          configuration. Settings come from environment variables (MAIL_ENABLED,
          MAIL_USERNAME, MAIL_PASSWORD, ALERT_RECIPIENT).
        </p>
        <button type="button" onClick={sendTestEmail} disabled={mailBusy}>
          {mailBusy ? 'Sending…' : 'Send test email'}
        </button>
      </section>
    </div>
  )
}
