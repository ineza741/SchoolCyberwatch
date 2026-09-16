import { API_BASE_URL } from '../config/api'
import { clearStoredAuth, getAuthHeader } from './auth'

/**
 * Central API layer. Every backend call in the app goes through here:
 * - attaches the JWT from services/auth.js
 * - parses JSON
 * - normalizes errors into Error objects with a friendly message
 * - on 401 clears the stored session (caller decides to redirect)
 */
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
    const error = new Error('Your session has expired. Please sign in again.')
    error.status = 401
    throw error
  }

  const data = await response.json().catch(() => null)
  if (!response.ok) {
    const error = new Error((data && data.error) || `Request failed (HTTP ${response.status})`)
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
