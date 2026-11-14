export type Role = 'admin' | 'analyst' | 'viewer'

export interface User {
  id: number
  email: string
  name: string
  role: Role
  totp_enabled: boolean
}

export interface Me {
  user: User
  require_mfa: boolean
  canary_zone: string
}

export type Verdict = 'proved' | 'probable' | 'exposed' | 'patched' | 'inconclusive' | 'error' | ''

export interface Asset {
  id: number
  host: string
  kind: 'domain' | 'ip' | 'cidr'
  tags: string[]
  scheme: 'http' | 'https'
  port: number
  proof_method: 'dns_txt' | 'well_known' | 'allowlist'
  proof_token: string
  proof_token_expires: string
  proof_status: 'pending' | 'valid' | 'failed'
  proof_detail: string
  proof_checked_at: string | null
  proof_valid_until: string | null
  resolved_ips: string[]
  created_at: string
  owned: boolean
  last_verdict: Verdict
  last_checker: string
  txt_name?: string
  txt_value?: string
  well_known_url?: string
  default_url: string
}

export interface CheckerInfo {
  id: string
  name: string
  cves: string[]
  product: string
  mode: 'canary' | 'fingerprint'
  description: string
  proof: string
  sent: string
  remediation: string[]
  references: string[]
  tags: string[]
  lab_validated: boolean
  lab_note: string
  source: 'builtin' | 'plugin'
  version?: string
  publisher?: string
  signed: boolean
  requires_file_canary: boolean
  file_callback: boolean
}

export interface Point {
  id: string
  location: string
  status?: number
  error?: string
}

export interface Hit {
  CallbackID: number
  At: string
  Proto: string
  QType: string
  QName: string
  Point: string
  Source: string
  SourceMatches: boolean
}

export interface CheckDetailJSON {
  resolved_ips?: string[]
  canary?: string
  canary_expires_at?: string
  wait_seconds?: number
  points?: Point[]
  evidence?: Record<string, string>
  callback?: Hit
  delta_ms?: number
  error?: string
}

export interface Check {
  id: number
  campaign_id: number
  asset_id: number
  asset_host: string
  target_url: string
  checker: string
  checker_name: string
  cves: string[]
  mode: 'canary' | 'fingerprint'
  status: 'queued' | 'running' | 'waiting' | 'done' | 'error' | 'cancelled'
  verdict: Verdict
  summary: string
  detail: CheckDetailJSON
  created_at: string
  started_at: string | null
  sent_at: string | null
  finished_at: string | null
}

export interface Callback {
  id: number
  received_at: string
  proto: string
  qtype: string
  qname: string
  point: string
  source_ip: string
  raw: string
  status: 'correlated' | 'duplicate' | 'expired' | 'replay' | 'unknown' | 'selftest' | 'honeytoken'
  source_matches: boolean | null
  check_id: number | null
  campaign_id: number | null
  asset_host: string
  checker: string
}

export interface Campaign {
  id: number
  asset_id: number
  asset_host: string
  target_url: string
  created_by: string
  created_at: string
  cancelled: boolean
  total: number
  pending: number
  proved: number
  probable: number
  checks?: Check[]
  events?: Callback[]
}

export interface CheckFull extends Check {
  info: CheckerInfo
  callbacks: Callback[]
}

export interface Dashboard {
  assets_total: number
  assets_owned: number
  assets_renew: number
  checks_30d: number
  fingerprint_30d: number
  proved_30d: number
  probable_30d: number
  running: number
  last_callback: string | null
  alerts: Callback[]
  recent: Check[]
  renew: Asset[]
}

export interface Receiver {
  zone: string
  ns_name: string
  ip: string
  dns_addr: string
  http_addr: string
  dns_up: boolean
  http_up: boolean
  resolvers: string[]
  records: string[]
}

export interface ReportRow {
  id: number
  title: string
  summary: string
  format: 'html' | 'json'
  sha256: string
  size: number
  created_by: string
  created_at: string
}

export interface AuditEntry {
  id: number
  at: string
  actor: string
  action: string
  detail: string
  ip: string
  hash: string
}

export interface UserRow {
  id: number
  email: string
  name: string
  role: Role
  totp_enabled: boolean
  disabled: boolean
  created_at: string
  last_login_at: string | null
}

export interface AllowRow {
  id: number
  cidr: string
  reason: string
  added_by: string
  created_at: string
  review_at: string
}

export interface Settings {
  canary_ttl_minutes: number
  wait_seconds: number
  checks_per_asset_day: number
  checks_per_user_hour: number
  allow_unsigned_plugins: boolean
}

export interface PluginRow {
  id: string
  version: string
  name: string
  sha256: string
  publisher: string
  signed: boolean
  enabled: boolean
  source: string
  installed_by: string
  installed_at: string
  content: string
}

export interface PluginPreview {
  id: string
  name: string
  version: string
  cves: string[]
  mode: 'canary' | 'fingerprint'
  product: string
  description: string
  sent: string
  steps: string[]
  requires_file_canary: boolean
  sha256: string
  signed: boolean
  publisher: string
  signature_error: string
  installable: boolean
  content: string
  replaces?: string
}

export interface RegistryEntry {
  id: string
  name: string
  version: string
  cves: string[]
  mode: 'canary' | 'fingerprint'
  product: string
  description: string
  url: string
  installed: string
}

export interface PublisherRow {
  id: number
  name: string
  public_key: string
  key_id: string
  builtin: boolean
  added_by: string
  created_at: string
}

export interface FileCanary {
  path: string
  token: string
  content: string
  created_at: string
  linux: string
  windows: string
}
