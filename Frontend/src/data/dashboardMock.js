export const dashboardSummary = [
  { label: 'Monitored computers', value: '24', tone: 'neutral' },
  { label: 'Active alerts', value: '8', tone: 'violet' },
  { label: 'Critical and high', value: '3', tone: 'critical' },
  { label: 'Open incidents', value: '2', tone: 'warning' },
  { label: 'Resolved incidents', value: '14', tone: 'success' },
]

export const recentAlerts = [
  { id: 1, name: 'Possible brute force', device: 'Examination-PC', severity: 'Critical', time: '10:35', status: 'New' },
  { id: 2, name: 'Failed login', device: 'Admin-PC', severity: 'Medium', time: '10:30', status: 'New' },
  { id: 3, name: 'Protected file modified', device: 'Examination-PC', severity: 'High', time: '09:45', status: 'Investigating' },
]
