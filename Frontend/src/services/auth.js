import { API_BASE_URL } from '../config/api'

const STORAGE_KEY = 'schoolcyberwatch.auth'

/**
 * Calls POST /api/auth/login on the Spring Boot backend.
 * On success the returned auth object { token, email, fullName }
 * is persisted and also returned to the caller.
 * Throws an Error with a friendly message on failure.
 */
export async function login(email, password) {
  let response
  try {
    response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
  } catch {
    throw new Error('Cannot reach the sign-in service. Is the backend running?')
  }

  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    throw new Error(data.error || `Sign-in failed (HTTP ${response.status})`)
  }

  const auth = { token: data.token, email: data.email, fullName: data.fullName }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(auth))
  return auth
}

/**
 * Calls POST /api/auth/register on the Spring Boot backend.
 * On success the account is created and the returned auth object
 * { token, email, fullName } is persisted (auto sign-in) and returned.
 * Throws an Error with a friendly message on failure.
 */
export async function register(email, fullName, password) {
  let response
  try {
    response = await fetch(`${API_BASE_URL}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, fullName, password }),
    })
  } catch {
    throw new Error('Cannot reach the registration service. Is the backend running?')
  }

  const data = await response.json().catch(() => ({}))
  if (!response.ok) {
    throw new Error(data.error || `Registration failed (HTTP ${response.status})`)
  }

  const auth = { token: data.token, email: data.email, fullName: data.fullName }
  localStorage.setItem(STORAGE_KEY, JSON.stringify(auth))
  return auth
}

export function getStoredAuth() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    const auth = raw ? JSON.parse(raw) : null
    return auth && auth.token ? auth : null
  } catch {
    return null
  }
}

export function clearStoredAuth() {
  localStorage.removeItem(STORAGE_KEY)
}

/** Authorization header for authenticated API calls. */
export function getAuthHeader() {
  const auth = getStoredAuth()
  return auth && auth.token ? { Authorization: `Bearer ${auth.token}` } : {}
}
