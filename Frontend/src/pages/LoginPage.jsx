import { useState } from 'react'
import BrandMark from '../components/BrandMark'
import { login, register } from '../services/auth'

export default function LoginPage({ onLogin, onBack, onToggleTheme, isDark }) {
  const [mode, setMode] = useState('signin') // 'signin' | 'register'
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [fullName, setFullName] = useState('')
  const [error, setError] = useState('')
  const [submitting, setSubmitting] = useState(false)

  function toggleMode(nextMode) {
    setMode(nextMode)
    setError('')
    setPassword('')
    setConfirmPassword('')
  }

  async function handleSubmit(event) {
    event.preventDefault()
    setError('')

    if (mode === 'register' && password !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    setSubmitting(true)
    try {
      if (mode === 'register') {
        await register(email, fullName, password)
      } else {
        await login(email, password)
      }
      onLogin()
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <main className="login-page">
      <section>
        <div className="login-brand">
          <BrandMark />
          <button className="theme-switch" onClick={onToggleTheme} type="button">{isDark ? 'Light' : 'Dark'}</button>
        </div>
        <p>SCHOOL CYBERWATCH</p>
        <h1>{mode === 'register' ? 'Create account.' : 'Welcome back.'}</h1>
        <h2>{mode === 'register'
          ? 'Register your school ICT administrator account.'
          : 'Sign in to view your school security workspace.'}</h2>
        <form onSubmit={handleSubmit}>
          {mode === 'register' ? (
            <label>
              Full name
              <input
                value={fullName}
                required
                onChange={(event) => setFullName(event.target.value)}
                placeholder="e.g. Ineza Darryl"
                autoComplete="name"
              />
            </label>
          ) : null}
          <label>
            Email or username
            <input
              type="email"
              value={email}
              required
              onChange={(event) => setEmail(event.target.value)}
              placeholder="name@school.edu.rw"
              autoComplete={mode === 'register' ? 'new-email' : 'username'}
            />
          </label>
          <label>
            Password
            <input
              type="password"
              value={password}
              required
              minLength={mode === 'register' ? 8 : undefined}
              onChange={(event) => setPassword(event.target.value)}
              placeholder={mode === 'register' ? 'At least 8 characters' : 'Enter your password'}
              autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
            />
          </label>
          {mode === 'register' ? (
            <label>
              Confirm password
              <input
                type="password"
                value={confirmPassword}
                required
                onChange={(event) => setConfirmPassword(event.target.value)}
                placeholder="Repeat the password"
                autoComplete="new-password"
              />
            </label>
          ) : null}
          {error ? <p className="login-error" role="alert">{error}</p> : null}
          <button type="submit" disabled={submitting}>
            {submitting
              ? (mode === 'register' ? 'Creating account…' : 'Signing in…')
              : (mode === 'register' ? 'Create account →' : 'Sign in →')}
          </button>
        </form>
        {mode === 'register' ? (
          <small>Already have an account?{' '}
            <button className="link-switch" onClick={() => toggleMode('signin')} type="button">Sign in</button>
          </small>
        ) : (
          <small>Authorized school ICT personnel only.{' '}
            <button className="link-switch" onClick={() => toggleMode('register')} type="button">Create an account</button>
          </small>
        )}
        <button className="back" onClick={onBack} type="button">← Back to homepage</button>
      </section>
      <aside>
        <span>✓</span>
        <p>FOCUSED MONITORING</p>
        <h2>Security information that feels manageable.</h2>
      </aside>
    </main>
  )
}
