import { API_BASE_URL } from '../config/api'

const getToken = () => localStorage.getItem('token')

const headers = () => ({
  'Content-Type': 'application/json',
  ...(getToken() ? { Authorization: `Bearer ${getToken()}` } : {})
})

export const login = async (email, password) => {
  const response = await fetch(`${API_BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  })
  if (!response.ok) throw new Error('Invalid credentials')
  const data = await response.json()
  localStorage.setItem('token', data.token)
  return data
}

export const getDashboardSummary = async () => {
  const response = await fetch(`${API_BASE_URL}/dashboard/summary`, { headers: headers() })
  if (!response.ok) throw new Error('Failed to fetch summary')
  return response.json()
}

export const getAlerts = async () => {
  const response = await fetch(`${API_BASE_URL}/dashboard/alerts`, { headers: headers() })
  if (!response.ok) throw new Error('Failed to fetch alerts')
  return response.json()
}
