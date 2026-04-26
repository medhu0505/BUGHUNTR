export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanStatus = 'idle' | 'running' | 'complete';
export type FindingStatus = 'open' | 'confirmed' | 'false-positive' | 'resolved';

export interface VulnerableObject {
  url: string;
  type: string;
  description?: string;
}

export interface Finding {
  id: string;
  asset: string;
  finding: string;
  severity: Severity;
  status: FindingStatus;
  module: string;
  timestamp: string;
  details: string;
  vulnerableObjects?: VulnerableObject[];
}

export interface ScanResult {
  scanId: string;
  module: string;
  target: string;
  status: ScanStatus;
  startTime: string;
  endTime?: string;
  findings: Finding[];
}

export interface ModuleDefinition {
  id: string;
  name: string;
  icon: string;
  path: string;
}

export interface ModuleOption {
  label: string;
  type: "toggle" | "checkbox" | "number";
  default: boolean | number;
}

export interface DashboardStats {
  totalScans: number;
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface ActivityEntry {
  time: string;
  type: Severity;
  msg: string;
}

export const MODULES: ModuleDefinition[] = [
  { id: 'subdomain-takeover', name: 'Subdomain Takeover', icon: 'Globe', path: '/scanner/subdomain-takeover' },
  { id: 's3-buckets', name: 'S3/Blob Bucket Checker', icon: 'Database', path: '/scanner/s3-buckets' },
  { id: 'cors', name: 'CORS Misconfiguration', icon: 'Shield', path: '/scanner/cors' },
  { id: 'sensitive-files', name: 'Sensitive File Exposure', icon: 'FileWarning', path: '/scanner/sensitive-files' },
  { id: 'api-key-leak', name: 'API Key Leak Detector', icon: 'Key', path: '/scanner/api-key-leak' },
  { id: 'open-redirect', name: 'Open Redirect Fuzzer', icon: 'ExternalLink', path: '/scanner/open-redirect' },
  { id: 'clickjacking', name: 'CORS + Clickjacking', icon: 'Layers', path: '/scanner/clickjacking' },
  { id: 'dns-zone-transfer', name: 'DNS Zone Transfer', icon: 'Server', path: '/scanner/dns-zone-transfer' },
  { id: 'spf-dmarc', name: 'SPF/DMARC Checker', icon: 'Mail', path: '/scanner/spf-dmarc' },
  { id: 'rate-limit', name: 'Rate Limit Tester', icon: 'Gauge', path: '/scanner/rate-limit' },
] as const;

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'bg-destructive text-destructive-foreground',
  high: 'bg-warning text-warning-foreground',
  medium: 'bg-accent text-accent-foreground',
  low: 'bg-info text-info-foreground',
  info: 'bg-muted text-muted-foreground',
};

const randomId = () => Math.random().toString(36).substring(2, 10);

export const getMockFindings = (): Finding[] => [
  {
    id: randomId(),
    asset: "api.example.com",
    finding: "CORS misconfiguration detected",
    severity: "high",
    status: "open",
    module: "cors",
    timestamp: new Date(Date.now() - 3600000).toISOString(),
    details: "The API endpoint reflects arbitrary origins in CORS headers without credentials restriction.",
    vulnerableObjects: [{ url: "https://api.example.com/v1/users", type: "endpoint", description: "Reflects any origin" }],
  },
  {
    id: randomId(),
    asset: "example.com",
    finding: "Sensitive file exposure",
    severity: "critical",
    status: "confirmed",
    module: "sensitive-files",
    timestamp: new Date(Date.now() - 7200000).toISOString(),
    details: "Publicly accessible .env file found containing database credentials.",
    vulnerableObjects: [{ url: "https://example.com/.env", type: "file" }],
  },
  {
    id: randomId(),
    asset: "cdn.example.com",
    finding: "Subdomain takeover vulnerability",
    severity: "critical",
    status: "confirmed",
    module: "subdomain-takeover",
    timestamp: new Date(Date.now() - 10800000).toISOString(),
    details: "Dangling CNAME record pointing to deprovisioned Netlify deployment.",
    vulnerableObjects: [{ url: "cdn.example.com", type: "subdomain", description: "CNAME: cdn-example.netlify.app (NXDOMAIN)" }],
  },
  {
    id: randomId(),
    asset: "s3-backup.example.com",
    finding: "S3 bucket publicly readable",
    severity: "high",
    status: "open",
    module: "s3-buckets",
    timestamp: new Date(Date.now() - 14400000).toISOString(),
    details: "S3 bucket is publicly accessible for listing. Directory enumeration is possible.",
    vulnerableObjects: [{ url: "https://s3-backup.s3.amazonaws.com", type: "bucket" }],
  },
  {
    id: randomId(),
    asset: "example.com",
    finding: "Open redirect vulnerability",
    severity: "medium",
    status: "false-positive",
    module: "open-redirect",
    timestamp: new Date(Date.now() - 18000000).toISOString(),
    details: "Redirect parameter accepts external URLs. Could be used in phishing attacks.",
    vulnerableObjects: [{ url: "https://example.com/?next=", type: "parameter" }],
  },
  {
    id: randomId(),
    asset: "api.example.com",
    finding: "Rate limiting not enforced",
    severity: "medium",
    status: "open",
    module: "rate-limit",
    timestamp: new Date(Date.now() - 21600000).toISOString(),
    details: "API endpoint accepts 100+ requests per second without rate limiting. Could enable brute force attacks.",
  },
  {
    id: randomId(),
    asset: "example.com",
    finding: "Missing DMARC policy",
    severity: "medium",
    status: "open",
    module: "spf-dmarc",
    timestamp: new Date(Date.now() - 25200000).toISOString(),
    details: "No DMARC record found. Domain is susceptible to email spoofing.",
  },
  {
    id: randomId(),
    asset: "legacy.example.com",
    finding: "Clickjacking vulnerability",
    severity: "medium",
    status: "open",
    module: "clickjacking",
    timestamp: new Date(Date.now() - 28800000).toISOString(),
    details: "Missing X-Frame-Options and CSP frame-ancestors headers. Page can be framed in iframes.",
  },
  {
    id: randomId(),
    asset: "example.com",
    finding: "DNS zone transfer allowed",
    severity: "high",
    status: "confirmed",
    module: "dns-zone-transfer",
    timestamp: new Date(Date.now() - 32400000).toISOString(),
    details: "NS servers allow unauthenticated zone transfers. All DNS records exposed.",
    vulnerableObjects: [{ url: "example.com", type: "zone", description: "Transferred 47 records" }],
  },
  {
    id: randomId(),
    asset: "app.example.com",
    finding: "API key exposed in JavaScript",
    severity: "critical",
    status: "confirmed",
    module: "api-key-leak",
    timestamp: new Date(Date.now() - 36000000).toISOString(),
    details: "AWS API key found in minified JavaScript source code.",
    vulnerableObjects: [{ url: "https://app.example.com/static/app.js", type: "script", description: "AKIA2ZXQM7VWPQRSTUV9" }],
  },
];

export const getStats = (): DashboardStats => {
  const findings = getMockFindings();
  return {
    totalScans: 42,
    totalFindings: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
  };
};

export const MOCK_LOG_LINES = [
  '[*] Initializing scan engine...',
  '[*] Loading target: {target}',
  '[*] Resolving DNS records...',
  '[+] Found 12 subdomains',
  '[*] Probing endpoints...',
  '[*] Checking HTTP headers...',
  '[!] Potential vulnerability detected',
  '[*] Verifying finding...',
  '[+] Confirmed: vulnerability is exploitable',
  '[*] Generating report...',
  '[*] Scan complete. {count} findings.',
];

export const getModuleConfig = (moduleId: string) => {
  const configs: Record<string, ModuleOption[]> = {
    'subdomain-takeover': [
      { label: 'Check CNAME records', type: 'toggle', default: true },
      { label: 'Check A records', type: 'toggle', default: true },
      { label: 'Verify takeover feasibility', type: 'checkbox', default: true },
      { label: 'Include wildcard check', type: 'checkbox', default: false },
    ],
    's3-buckets': [
      { label: 'Check public READ', type: 'toggle', default: true },
      { label: 'Check public WRITE', type: 'toggle', default: true },
      { label: 'Enumerate objects', type: 'checkbox', default: false },
      { label: 'Check Azure Blob', type: 'checkbox', default: true },
    ],
    'cors': [
      { label: 'Test null origin', type: 'toggle', default: true },
      { label: 'Test wildcard origin', type: 'toggle', default: true },
      { label: 'Check credentials flag', type: 'checkbox', default: true },
    ],
    default: [
      { label: 'Deep scan mode', type: 'toggle', default: false },
      { label: 'Follow redirects', type: 'toggle', default: true },
      { label: 'Verbose output', type: 'checkbox', default: true },
    ],
  };
  return configs[moduleId] || configs.default;
};

export const ACTIVITY_FEED: ActivityEntry[] = [
  { time: new Date(Date.now() - 3600000).toISOString(), type: "critical", msg: "Critical: API key exposed in JavaScript on app.example.com" },
  { time: new Date(Date.now() - 7200000).toISOString(), type: "critical", msg: "Critical: Sensitive file exposure detected at example.com/.env" },
  { time: new Date(Date.now() - 10800000).toISOString(), type: "critical", msg: "Critical: Subdomain takeover on cdn.example.com (Netlify)" },
  { time: new Date(Date.now() - 14400000).toISOString(), type: "high", msg: "High: S3 bucket publicly readable at s3-backup.example.com" },
  { time: new Date(Date.now() - 18000000).toISOString(), type: "high", msg: "High: CORS misconfiguration on api.example.com" },
  { time: new Date(Date.now() - 21600000).toISOString(), type: "high", msg: "High: DNS zone transfer allowed for example.com" },
  { time: new Date(Date.now() - 25200000).toISOString(), type: "medium", msg: "Medium: Open redirect vulnerability on example.com" },
  { time: new Date(Date.now() - 28800000).toISOString(), type: "medium", msg: "Medium: Clickjacking possible on legacy.example.com" },
  { time: new Date(Date.now() - 32400000).toISOString(), type: "medium", msg: "Medium: Missing DMARC policy on example.com domain" },
  { time: new Date(Date.now() - 36000000).toISOString(), type: "medium", msg: "Medium: Rate limiting not enforced on api.example.com" },
];

export const H1_REPORT_TEMPLATE = (finding: Finding) => `
## Summary
${finding.finding}

## Asset
${finding.asset}

## Severity
${finding.severity.toUpperCase()}

## Description
${finding.details}

## Steps to Reproduce
1. Navigate to ${finding.asset}
2. Observe the vulnerability as described above

## Impact
This vulnerability could allow an attacker to...

## Remediation
[Describe recommended fix]

## References
- OWASP: https://owasp.org
`;
