import { HelpCircle, Shield, Zap, Database, FileText, Github } from "lucide-react";

export default function AboutPage() {
  const features = [
    {
      icon: Shield,
      title: "Security Scanner Modules",
      description: "10 specialized security scanners designed to detect common web vulnerabilities including subdomain takeovers, S3 misconfigurations, CORS issues, sensitive file exposure, API key leaks, and more."
    },
    {
      icon: Zap,
      title: "Real-time Scan Progress",
      description: "Monitor scan progress in real-time via streaming terminal logs. Active scans continue in the backend even if you navigate to another page."
    },
    {
      icon: Database,
      title: "Persistent Findings Database",
      description: "All findings are automatically saved to a SQLite database. Scan history can be reviewed, filtered, exported, and selectively deleted."
    },
    {
      icon: FileText,
      title: "Reports & Export",
      description: "Generate detailed reports with vulnerable objects, affected assets, confidence signals, and remediation guidance. Export findings in JSON or CSV."
    },
  ];

  const modules = [
    { name: "Subdomain Takeover", desc: "Guided 4-stage workflow: enumerate, DNS triage, CNAME vuln scan, and verification" },
    { name: "S3/Blob Bucket Checker", desc: "Scans AWS S3 and Azure Blob storage; avoids flagging locked (403) buckets as vulnerabilities" },
    { name: "CORS Misconfiguration", desc: "Tests for overly permissive CORS policies allowing unauthorized cross-origin requests" },
    { name: "Sensitive File Exposure", desc: "Finds exposed .env, .git, wp-config.php, and other sensitive files" },
    { name: "API Key Leak Detector", desc: "Searches JavaScript bundles and source code for hardcoded API credentials" },
    { name: "Open Redirect Fuzzer", desc: "Flags only real external 3xx redirects with out-of-scope Location targets" },
    { name: "CORS + Clickjacking", desc: "Verifies X-Frame-Options headers and tests clickjacking vulnerability" },
    { name: "DNS Zone Transfer", desc: "Attempts zone transfers to enumerate internal DNS records and hostnames" },
    { name: "SPF/DMARC Checker", desc: "Analyzes email authentication policies for configuration weaknesses" },
    { name: "Rate Limit Tester", desc: "Probes endpoints for missing or misconfigured rate limiting" },
  ];

  const sections = [
    {
      title: "Dashboard",
      desc: "Central view showing total scans, findings by severity, and recent activity feed"
    },
    {
      title: "Scanner Pages",
      desc: "Run targeted scans with module options, real-time logs, Enter-to-run, clear logs/results controls, and background scan resume"
    },
    {
      title: "Reports Center",
      desc: "Review all findings across all scans. Filter by severity, module, and status. Export findings and generate bug bounty reports"
    },
    {
      title: "Scan History",
      desc: "Track all scanned targets with timestamps, scan duration, and total findings. Selectively delete scans you no longer need"
    },
  ];

  return (
    <div className="space-y-8">
      {/* Attribution Header */}
      <div className="bg-gradient-to-r from-primary/10 to-primary/5 rounded-lg border border-primary/20 p-6 space-y-3">
        <div className="flex items-center gap-2">
          <Github className="h-5 w-5 text-primary" />
          <h2 className="text-lg font-bold text-primary">BUGHUNTR v4.2</h2>
        </div>
        <p className="text-sm leading-relaxed">
          <span className="font-semibold">Made by Medhansh Sharma</span> <span className="text-muted-foreground">(aka StickyBugger)</span>
        </p>
        <p className="text-xs text-muted-foreground">
          A professional bug bounty hunter and a cybersecurity expert [H4CKER].
        </p>
      </div>

      {/* Main Header */}
      <div className="space-y-2">
        <h1 className="text-4xl font-bold neon-text tracking-wider">ABOUT BUGHUNTR</h1>
        <p className="text-muted-foreground text-lg">Educational tool for learning about web security vulnerabilities</p>
      </div>

      {/* Overview */}
      <div className="bg-card rounded-lg border border-border neon-border p-6 space-y-4">
        <h2 className="text-xl font-bold flex items-center gap-2">
          <HelpCircle className="h-5 w-5 text-primary" />
          What is BUGHUNTR?
        </h2>
        <p className="text-sm leading-relaxed">
          BUGHUNTR is an educational security learning tool that demonstrates common web vulnerability detection techniques. It combines multiple security scanner modules to show how automated vulnerability assessment works, making it ideal for learning about web security.
        </p>
        <p className="text-sm leading-relaxed">
          <strong className="text-warning">⚠️ Disclaimer:</strong> Do anything you want to do with this, IDC, im a hacker why do i waarn you about ethicality... LOL!! 
        </p>
      </div>

      {/* Core Features */}
      <div className="grid md:grid-cols-2 gap-4">
        {features.map((feat) => {
          const Icon = feat.icon;
          return (
            <div key={feat.title} className="bg-card rounded-lg border border-border p-4 space-y-2 hover:border-primary/50 hover:bg-card/80 transition-all">
              <div className="flex items-start gap-3">
                <Icon className="h-5 w-5 text-primary shrink-0 mt-0.5" />
                <div className="space-y-1">
                  <h3 className="font-semibold text-sm">{feat.title}</h3>
                  <p className="text-xs text-muted-foreground">{feat.description}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Sections Guide */}
      <div className="space-y-4">
        <h2 className="text-xl font-bold">SECTIONS & FEATURES</h2>
        <div className="grid md:grid-cols-2 gap-4">
          {sections.map((sec) => (
            <div key={sec.title} className="bg-card rounded-lg border border-border p-4 space-y-2">
              <h3 className="font-semibold text-sm neon-text">{sec.title}</h3>
              <p className="text-xs text-muted-foreground">{sec.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Scanner Modules */}
      <div className="space-y-4">
        <h2 className="text-xl font-bold">AVAILABLE SCANNER MODULES</h2>
        <div className="grid md:grid-cols-2 gap-3">
          {modules.map((mod) => (
            <div key={mod.name} className="bg-card rounded-lg border border-border p-3">
              <p className="font-semibold text-sm">{mod.name}</p>
              <p className="text-xs text-muted-foreground mt-1">{mod.desc}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Terminology */}
      <div className="bg-muted/30 rounded-lg border border-border p-6 space-y-4">
        <h2 className="text-lg font-bold">KEY TERMINOLOGY</h2>
        <div className="grid md:grid-cols-2 gap-4 text-sm">
          <div>
            <p className="font-semibold text-primary">Finding</p>
            <p className="text-muted-foreground">A detected vulnerability or security issue</p>
          </div>
          <div>
            <p className="font-semibold text-primary">Vulnerable Object</p>
            <p className="text-muted-foreground">Specific URL, file, endpoint, or resource where the vulnerability exists</p>
          </div>
          <div>
            <p className="font-semibold text-primary">Severity</p>
            <p className="text-muted-foreground">Impact rating: Critical, High, Medium, Low, or Info</p>
          </div>
          <div>
            <p className="font-semibold text-primary">Status</p>
            <p className="text-muted-foreground">Open, Confirmed, False Positive, or Resolved</p>
          </div>
          <div>
            <p className="font-semibold text-primary">Module</p>
            <p className="text-muted-foreground">Specialized scanner for a specific vulnerability type</p>
          </div>
          <div>
            <p className="font-semibold text-primary">Scan Target</p>
            <p className="text-muted-foreground">Domain or URL being scanned for vulnerabilities</p>
          </div>
        </div>
      </div>

      {/* Production Features */}
      <div className="bg-primary/10 rounded-lg border border-primary/20 p-6 space-y-3">
        <h2 className="text-lg font-bold text-primary">PRODUCTION-GRADE FEATURES</h2>
        <ul className="space-y-2 text-sm">
          <li className="flex items-start gap-2">
            <span className="text-primary font-bold">✓</span>
            <span>Persistent storage with SQLite database for all findings and scans</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-primary font-bold">✓</span>
            <span>RESTful API backend for scanner integration, automation, and staged takeover workflow</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-primary font-bold">✓</span>
            <span>Real-time SSE streaming for scan progress monitoring and reconnect behavior</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-primary font-bold">✓</span>
            <span>Detailed vulnerable object tracking for each finding</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-primary font-bold">✓</span>
            <span>Complete scan history with timestamps, metrics, and clear-history controls</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-primary font-bold">✓</span>
            <span>Multiple export formats (JSON, CSV) for reporting</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-primary font-bold">✓</span>
            <span>Type-safe frontend with TypeScript and React Query</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-primary font-bold">✓</span>
            <span>CORS-enabled API for cross-origin requests</span>
          </li>
        </ul>
      </div>

      {/* Footer */}
      <div className="text-center text-xs text-muted-foreground pt-4 border-t border-border">
        <p>BUGHUNTR v1.0 — Security Vulnerability Scanner</p>
        <p className="mt-1">For responsible disclosure of vulnerabilities found with BUGHUNTR, contact the target organization's security team.</p>
      </div>
    </div>
  );
}
