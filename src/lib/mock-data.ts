export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ScanStatus = 'idle' | 'running' | 'complete';
export type FindingStatus = 'open' | 'confirmed' | 'false-positive' | 'resolved';

export interface Finding {
  id: string;
  asset: string;
  finding: string;
  severity: Severity;
  status: FindingStatus;
  module: string;
  timestamp: string;
  details: string;
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
  type: "toggle" | "checkbox";
  default: boolean;
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
  { id: 's3-bucket', name: 'S3/Blob Bucket Checker', icon: 'Database', path: '/scanner/s3-bucket' },
  { id: 'cors-misconfig', name: 'CORS Misconfiguration', icon: 'Shield', path: '/scanner/cors-misconfig' },
  { id: 'sensitive-files', name: 'Sensitive File Exposure', icon: 'FileWarning', path: '/scanner/sensitive-files' },
  { id: 'api-key-leak', name: 'API Key Leak Detector', icon: 'Key', path: '/scanner/api-key-leak' },
  { id: 'open-redirect', name: 'Open Redirect Fuzzer', icon: 'ExternalLink', path: '/scanner/open-redirect' },
  { id: 'clickjacking', name: 'CORS + Clickjacking', icon: 'Layers', path: '/scanner/clickjacking' },
  { id: 'dns-zone', name: 'DNS Zone Transfer', icon: 'Server', path: '/scanner/dns-zone' },
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

const MOCK_FINDINGS: Finding[] = [
  { id: randomId(), asset: 'staging.example.com', finding: 'Dangling CNAME → Heroku', severity: 'critical', status: 'open', module: 'subdomain-takeover', timestamp: '2025-04-14T08:23:00Z', details: 'CNAME record points to deprovisioned Heroku app. Subdomain can be claimed by attacker.' },
  { id: randomId(), asset: 's3://company-backups', finding: 'Public READ access on bucket', severity: 'critical', status: 'open', module: 's3-bucket', timestamp: '2025-04-14T07:15:00Z', details: 'S3 bucket allows unauthenticated LIST and GET operations. Contains database backups.' },
  { id: randomId(), asset: 'api.example.com', finding: 'CORS allows arbitrary origins', severity: 'high', status: 'confirmed', module: 'cors-misconfig', timestamp: '2025-04-14T06:45:00Z', details: 'Access-Control-Allow-Origin reflects request Origin header without validation.' },
  { id: randomId(), asset: 'example.com/.env', finding: 'Exposed .env file with DB creds', severity: 'critical', status: 'open', module: 'sensitive-files', timestamp: '2025-04-14T05:30:00Z', details: 'Environment file accessible at root containing DATABASE_URL, SECRET_KEY, and AWS credentials.' },
  { id: randomId(), asset: 'app.example.com/main.js', finding: 'Hardcoded Stripe API key', severity: 'high', status: 'open', module: 'api-key-leak', timestamp: '2025-04-13T22:10:00Z', details: 'sk_live_xxxx found in minified JavaScript bundle.' },
  { id: randomId(), asset: 'example.com/redirect', finding: 'Open redirect via ?url= param', severity: 'medium', status: 'open', module: 'open-redirect', timestamp: '2025-04-13T20:00:00Z', details: 'Redirect endpoint accepts arbitrary URLs. Can be used for phishing.' },
  { id: randomId(), asset: 'example.com', finding: 'Missing X-Frame-Options', severity: 'medium', status: 'open', module: 'clickjacking', timestamp: '2025-04-13T18:30:00Z', details: 'No X-Frame-Options or CSP frame-ancestors header. Page can be embedded in iframes.' },
  { id: randomId(), asset: 'ns1.example.com', finding: 'DNS zone transfer allowed', severity: 'high', status: 'confirmed', module: 'dns-zone', timestamp: '2025-04-13T16:15:00Z', details: 'AXFR query returns full zone file with internal hostnames and IP addresses.' },
  { id: randomId(), asset: 'example.com', finding: 'SPF record too permissive', severity: 'medium', status: 'open', module: 'spf-dmarc', timestamp: '2025-04-13T14:00:00Z', details: 'SPF includes +all mechanism. Any server can send email as example.com.' },
  { id: randomId(), asset: 'api.example.com/login', finding: 'No rate limiting on login', severity: 'high', status: 'open', module: 'rate-limit', timestamp: '2025-04-13T12:00:00Z', details: '1000 requests sent with no throttling. Brute force attack possible.' },
  { id: randomId(), asset: 'dev.example.com', finding: 'Dangling A record', severity: 'low', status: 'false-positive', module: 'subdomain-takeover', timestamp: '2025-04-12T10:00:00Z', details: 'A record points to unresponsive IP. Likely internal infrastructure.' },
  { id: randomId(), asset: 'example.com/wp-config.php.bak', finding: 'WordPress config backup', severity: 'high', status: 'resolved', module: 'sensitive-files', timestamp: '2025-04-12T08:00:00Z', details: 'Backup of WordPress config file accessible with database credentials.' },
];

export const getMockFindings = () => MOCK_FINDINGS;

export const getStats = () => {
  const findings = MOCK_FINDINGS;
  return {
    totalScans: 47,
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
    's3-bucket': [
      { label: 'Check public READ', type: 'toggle', default: true },
      { label: 'Check public WRITE', type: 'toggle', default: true },
      { label: 'Enumerate objects', type: 'checkbox', default: false },
      { label: 'Check Azure Blob', type: 'checkbox', default: true },
    ],
    'cors-misconfig': [
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

export const generateScanResults = (moduleId: string, target: string): Finding[] => {
  const moduleFindingsPool = MOCK_FINDINGS.filter(f => f.module === moduleId);
  if (moduleFindingsPool.length === 0) {
    return [{
      id: randomId(),
      asset: target,
      finding: 'No vulnerabilities detected',
      severity: 'info',
      status: 'open',
      module: moduleId,
      timestamp: new Date().toISOString(),
      details: 'Scan completed with no findings.',
    }];
  }
  return moduleFindingsPool.map(f => ({
    ...f,
    id: randomId(),
    asset: f.asset.replace('example.com', target),
    timestamp: new Date().toISOString(),
  }));
};

export const ACTIVITY_FEED = [
  { time: '08:23:15', type: 'critical' as Severity, msg: '[CRITICAL] Subdomain takeover on staging.example.com' },
  { time: '08:22:01', type: 'info' as Severity, msg: '[SCAN] S3 bucket scan started for example.com' },
  { time: '08:20:45', type: 'high' as Severity, msg: '[HIGH] CORS misconfiguration on api.example.com' },
  { time: '08:19:30', type: 'info' as Severity, msg: '[SCAN] DNS zone transfer check complete' },
  { time: '08:18:12', type: 'medium' as Severity, msg: '[MEDIUM] Open redirect found on example.com' },
  { time: '08:17:00', type: 'info' as Severity, msg: '[SCAN] Rate limit test started for api.example.com' },
  { time: '08:15:33', type: 'critical' as Severity, msg: '[CRITICAL] .env file exposed on example.com' },
  { time: '08:14:20', type: 'high' as Severity, msg: '[HIGH] API key leaked in main.js bundle' },
  { time: '08:12:05', type: 'info' as Severity, msg: '[COMPLETE] SPF/DMARC check finished' },
  { time: '08:10:00', type: 'low' as Severity, msg: '[LOW] Informational: dev.example.com A record dangling' },
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
