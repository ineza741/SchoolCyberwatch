import { API_BASE_URL } from '../config/api'
import { clearStoredAuth, getAuthHeader } from './auth'

/**
 * Central API layer. Every backend call in the app goes through here:
 * - attaches the JWT from services/auth.js
 * - parses JSON
 * - normalizes errors into Error objects with a friendly message
 * - on 401 clears the stored session and broadcasts an event so App
 *   can redirect to login exactly once (no redirect loops)
 */

const AUTH_EXPIRED_EVENT = 'scw:auth-expired'

/** Let App know the JWT died so it can show the login page. */
export function broadcastAuthExpired() {
  window.dispatchEvent(new CustomEvent(AUTH_EXPIRED_EVENT))
}

export function onAuthExpired(handler) {
  window.addEventListener(AUTH_EXPIRED_EVENT, handler)
  return () => window.removeEventListener(AUTH_EXPIRED_EVENT, handler)
}

export async function apiRequest(path, { method = 'GET', body } = {}) {
  let response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      method,
      headers: { 'Content-Type': 'application/json', ...getAuthHeader() },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  } catch {
    throw new Error('Cannot reach the backend. Is the Spring Boot server running on port 8080?')
  }

  if (response.status === 401) {
    clearStoredAuth()
    broadcastAuthExpired()
    const error = new Error('Your session has expired. Please sign in again.')
    error.status = 401
    throw error
  }

  const data = await response.json().catch(() => null)
  if (!response.ok) {
    const message = (data && (data.error || data.message)) || `Request failed (HTTP ${response.status})`
    const error = new Error(message)
    error.status = response.status
    throw error
  }
  return data
}

/** Convenience GET wrapper. */
export function apiGet(path) {
  return apiRequest(path)
}

/** Convenience POST wrapper. */
export function apiPost(path, body) {
  return apiRequest(path, { method: 'POST', body })
}
