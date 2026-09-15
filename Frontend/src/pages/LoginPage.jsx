import { useState } from 'react'
import BrandMark from '../components/BrandMark'

export default function LoginPage({ onLogin, onBack, onToggleTheme, isDark }) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  return <main className="login-page"><section><div className="login-brand"><BrandMark /><button className="theme-switch" onClick={onToggleTheme} type="button">{isDark ? 'Light' : 'Dark'}</button></div><p>SCHOOL CYBERWATCH</p><h1>Welcome back.</h1><h2>Sign in to view your school security workspace.</h2><form onSubmit={(event) => { event.preventDefault(); onLogin() }}><label>Email or username<input value={email} required onChange={(event) => setEmail(event.target.value)} placeholder="name@school.edu.rw" /></label><label>Password<input type="password" value={password} required onChange={(event) => setPassword(event.target.value)} placeholder="Enter your password" /></label><button type="submit">Sign in →</button></form><small>Accounts are created for authorized school ICT personnel.</small><button className="back" onClick={onBack} type="button">← Back to homepage</button></section><aside><span>✓</span><p>FOCUSED MONITORING</p><h2>Security information that feels manageable.</h2></aside></main>
}
