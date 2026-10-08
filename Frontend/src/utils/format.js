/**
 * Shared formatting helpers. Everything shown to the ICT administrator
 * goes through these so the whole app stays consistent:
 * - large counts are grouped (552886 -> "552,886")
 * - timestamps render in a compact local format
 * - alert types get friendly names mapped from the Wazuh rule ids
 * - optional fields that the backend left empty render as an em dash,
 *   never "null" or "undefined"
 */

const DASH = '—'

/** 552886 -> "552,886" (also handles strings from the backend). */
export function formatNumber(value) {
  if (value === null || value === undefined || value === '') return DASH
  const num = Number(value)
  if (Number.isNaN(num)) return String(value)
  return num.toLocaleString('en-US')
}

/** ISO timestamp -> "06 Oct, 23:28" (falls back to the raw value). */
export function formatTime(iso) {
  if (!iso) return DASH
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString('en-GB', {
    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit',
  })
}

/** ISO timestamp -> "06 Oct 2026, 23:28" for detail views. */
export function formatTimeFull(iso) {
  if (!iso) return DASH
  const date = new Date(iso)
  if (Number.isNaN(date.getTime())) return iso
  return date.toLocaleString('en-GB', {
    day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit',
  })
}

/** Optional field that may be missing -> readable dash. */
export function orDash(value) {
  if (value === null || value === undefined) return DASH
  const text = String(value).trim()
  return text === '' || text === 'N/A' ? DASH : text
}

/** Wazuh rule id -> friendly type name (mirrors the backend mapper). */
const TYPE_LABELS = {
  FAILED_LOGIN: 'Failed Login',
  BRUTE_FORCE: 'Brute Force',
  FILE_MODIFIED: 'File Modification',
  FILE_DELETED: 'File Deletion',
  MALWARE_DETECTED: 'Malware Detection',
  NETWORK_CONNECTION: 'Network Connection',
  NETWORK_SCAN: 'Possible Network Scan',
}

export function typeLabel(type) {
  return TYPE_LABELS[type] || 'Security Event'
}

/** Rule id -> type key, mirroring the backend SecurityEventMapper. */
export function typeFromRule(ruleId) {
  switch (String(ruleId)) {
    case '60122': return 'FAILED_LOGIN'
    case '100200': return 'BRUTE_FORCE'
    case '550': return 'FILE_MODIFIED'
    case '553': return 'FILE_DELETED'
    case '62123': return 'MALWARE_DETECTED'
    case '100300': return 'NETWORK_CONNECTION'
    case '100301': return 'NETWORK_SCAN'
    default: return ''
  }
}

/** The seven detections School CyberWatch monitors. */
export const KNOWN_TYPES = [
  'FAILED_LOGIN', 'BRUTE_FORCE', 'FILE_MODIFIED', 'FILE_DELETED',
  'MALWARE_DETECTED', 'NETWORK_CONNECTION', 'NETWORK_SCAN',
]

/** IP protocol number (as sent by the backend) -> readable name. */
const PROTOCOL_NAMES = {
  1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 58: 'ICMPv6',
}

export function protocolLabel(value) {
  if (value === null || value === undefined || value === '') return DASH
  return PROTOCOL_NAMES[Number(value)] || String(value)
}

export const SEVERITY_LEVELS = ['Critical', 'High', 'Medium', 'Low']
