"""
scanners.py — All BBH scanner modules.
Each scanner is a generator that yields dicts:
  {"type": "log", "message": str}
  {"type": "finding", "data": {...}}
  {"type": "complete"}
"""

import subprocess, dns.resolver, dns.query, dns.zone, requests, re, json, shutil, socket, os, logging, time
from pathlib import Path
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; BUGHUNTR/1.0; +https://github.com/medhu0505/BUGHUNTR)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "close",
}

MAX_SUBDOMAIN_LIST_SIZE = 1000
MAX_REQUEST_TIMEOUT = 120
MIN_REQUEST_TIMEOUT = 5

# ── DNS Resolver ──────────────────────────────────────────────────────────────

TAKEOVER_RESOLVER = dns.resolver.Resolver()
TAKEOVER_RESOLVER.nameservers = ["8.8.8.8", "1.1.1.1"]
TAKEOVER_RESOLVER.timeout = 3
TAKEOVER_RESOLVER.lifetime = 5

# ── Fingerprints ──────────────────────────────────────────────────────────────

TAKEOVER_FINGERPRINTS = [
    {"provider": "Heroku",       "patterns": ["herokudns.com", "herokuapp.com"],          "takeover": True, "status_match": "No such app"},
    {"provider": "GitHub Pages", "patterns": ["github.io", "githubusercontent.com"],       "takeover": True, "status_match": "There isn't a GitHub Pages site here"},
    {"provider": "AWS S3",       "patterns": ["s3.amazonaws.com", "s3-website", "amazonaws.com"], "takeover": True, "status_match": "NoSuchBucket"},
    {"provider": "Azure",        "patterns": ["azurewebsites.net", "cloudapp.net"],        "takeover": True, "status_match": "404 Web Site not found"},
    {"provider": "Fastly",       "patterns": ["fastly.net"],                               "takeover": True, "status_match": "Fastly error: unknown domain"},
    {"provider": "Netlify",      "patterns": ["netlify.app", "netlify.com"],               "takeover": True, "status_match": "Not Found"},
    {"provider": "Vercel",       "patterns": ["vercel.app", "now.sh"],                     "takeover": True, "status_match": "The deployment could not be found"},
    {"provider": "Shopify",      "patterns": ["myshopify.com", "shopify.com"],             "takeover": True, "status_match": "Sorry, this shop is currently unavailable"},
    {"provider": "Tumblr",       "patterns": ["tumblr.com"],                               "takeover": True, "status_match": "Whatever you were looking for doesn't currently exist"},
    {"provider": "WordPress",    "patterns": ["wordpress.com", "wpengine.com"],            "takeover": True, "status_match": "Do you want to register"},
    {"provider": "Typepad",      "patterns": ["typepad.com"],                              "takeover": True, "status_match": "Domain is not configured"},
    {"provider": "Surge.sh",     "patterns": ["surge.sh"],                                "takeover": True, "status_match": "project not found"},
    {"provider": "Ghost",        "patterns": ["ghost.io"],                                 "takeover": True, "status_match": "The thing you were looking for is no longer here"},
    {"provider": "Unbounce",     "patterns": ["unbouncepages.com"],                        "takeover": True, "status_match": "The requested URL was not found"},
    {"provider": "StatusPage",   "patterns": ["statuspage.io"],                            "takeover": True, "status_match": "Page Not Found"},
    {"provider": "Strikingly",   "patterns": ["strikinglydns.com"],                        "takeover": True, "status_match": "page not found"},
    {"provider": "Webflow",      "patterns": ["proxy.webflow.com", "webflow.io"],          "takeover": True, "status_match": "The page you are looking for doesn't exist"},
    {"provider": "Fly.io",       "patterns": ["fly.dev", "fly.io"],                        "takeover": True, "status_match": "404"},
    {"provider": "Render",       "patterns": ["onrender.com"],                             "takeover": True, "status_match": "not found"},
    {"provider": "Railway",      "patterns": ["railway.app"],                              "takeover": True, "status_match": "not found"},
    {"provider": "Pantheon",     "patterns": ["pantheonsite.io"],                          "takeover": True, "status_match": "The gods are wise"},
    {"provider": "Readme.io",    "patterns": ["readme.io", "readmessl.com"],               "takeover": True, "status_match": "Project doesnt exist"},
    {"provider": "Zendesk",      "patterns": ["zendesk.com"],                              "takeover": True, "status_match": "Oops, this page doesn't exist"},
    {"provider": "HubSpot",      "patterns": ["hubspot.net", "hs-sites.com"],              "takeover": True, "status_match": "Domain is not configured"},
    {"provider": "Intercom",     "patterns": ["custom.intercom.help"],                     "takeover": True, "status_match": "Uh oh. That page doesn't exist"},
    {"provider": "Pingdom",      "patterns": ["stats.pingdom.com"],                        "takeover": True, "status_match": "This public report page has not been activated"},
    {"provider": "Acquia",       "patterns": ["acquia-test.co"],                           "takeover": True, "status_match": "It looks like this is not a valid Acquia subscription"},
    {"provider": "AWS ELB",      "patterns": ["elb.amazonaws.com", "elasticloadbalancing.amazonaws.com"], "takeover": True, "status_match": ""},
    {"provider": "AWS CloudFront", "patterns": ["cloudfront.net"],                         "takeover": False, "status_match": "Bad request"},
]

SENSITIVE_PATHS = [
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/.git/config", "/.git/HEAD", "/.gitignore",
    "/config.json", "/config.yaml", "/config.yml",
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/wp-config.php", "/wp-config.php.bak",
    "/debug.log", "/error.log", "/access.log",
    "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/test.php",
    "/.DS_Store",
    "/credentials.json", "/credentials.yaml",
    "/secrets.yaml", "/secrets.json",
    "/api/swagger.json", "/api/openapi.json", "/openapi.yaml",
    "/.aws/credentials",
    "/config/database.yml", "/config/secrets.yml",
    "/dump.sql", "/database.sql",
    "/.htpasswd", "/.htaccess",
    "/robots.txt", "/sitemap.xml",
    "/package.json", "/composer.json",
    "/Dockerfile", "/docker-compose.yml",
    "/.travis.yml", "/.circleci/config.yml",
]

REDIRECT_PARAMS = [
    "url", "next", "redirect", "redirect_uri", "return", "returnTo",
    "goto", "destination", "continue", "forward", "target", "redir",
    "location", "back", "callback", "link", "out",
]

SKIP_DOMAINS = {
    "google.com", "www.google.com",
    "github.com", "www.github.com",
    "stackoverflow.com",
    "amazon.com", "www.amazon.com",
    "microsoft.com", "www.microsoft.com",
    "facebook.com", "www.facebook.com",
    "twitter.com", "www.twitter.com",
    "linkedin.com", "www.linkedin.com",
    "apple.com", "www.apple.com",
    "netflix.com", "www.netflix.com",
    "cloudflare.com", "www.cloudflare.com",
}

# ── Utility Functions ─────────────────────────────────────────────────────────

def log(msg: str) -> dict:
    return {"type": "log", "message": str(msg), "timestamp": datetime.utcnow().isoformat()}


def _make_finding(asset: str, detail: str, severity: str, description: str, h1_report: str,
                  module: str = "", vulnerable_objects: list = None) -> dict:
    """Create a normalized finding event dict."""
    vuln_objs = vulnerable_objects or [{"url": asset, "type": "endpoint", "description": description}]
    return {
        "type": "finding",
        "data": {
            "asset": asset,
            "finding": description,
            "severity": severity,
            "details": detail,
            "evidence": json.dumps({"detail": detail}),
            "h1_report": h1_report,
            "vulnerable_objects": json.dumps(vuln_objs),
        }
    }


def _as_domain(target: str) -> str:
    value = (target or "").strip()
    if not value:
        return ""
    if "://" not in value:
        return value.split("/")[0].strip().lower()
    parsed = urlparse(value)
    return (parsed.hostname or "").strip().lower()


def _as_url(target: str) -> str:
    value = (target or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = f"https://{value}"
    return value


def _base_domain(host: str) -> str:
    parts = [p for p in (host or "").split(".") if p]
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])


def _should_skip_domain(target: str) -> bool:
    domain = _as_domain(target).lower()
    base = _base_domain(domain)
    return base in SKIP_DOMAINS or domain in SKIP_DOMAINS


def _validate_url(url: str) -> bool:
    try:
        if not url or not isinstance(url, str):
            return False
        parsed = urlparse(url)
        return bool(parsed.scheme in ("http", "https") and parsed.netloc)
    except Exception:
        return False


def _command_exists(name: str) -> bool:
    return _resolve_tool_path(name) is not None


def _resolve_tool_path(name: str):
    direct = shutil.which(name)
    if direct:
        return direct
    home = Path.home()
    candidates = [
        home / "go" / "bin" / f"{name}.exe",
        home / "go" / "bin" / name,
        Path.cwd() / "venv" / "Scripts" / f"{name}.exe",
        Path.cwd() / ".." / "venv" / "Scripts" / f"{name}.exe",
        Path.cwd() / f"{name}.exe",
        Path.cwd() / name,
    ]
    for c in candidates:
        if c.exists():
            return str(c.resolve())
    return None


def _get_fingerprint(cname: str):
    cname = (cname or "").lower().rstrip(".")
    for fp in TAKEOVER_FINGERPRINTS:
        if any(pattern in cname for pattern in fp["patterns"]):
            return fp
    return None


def _detect_provider(cname: str) -> str:
    fp = _get_fingerprint(cname)
    return fp["provider"] if fp else "Unknown"


def _takeover_severity(subdomain: str) -> str:
    sub = subdomain.lower()
    if any(k in sub for k in ["auth", "login", "sso", "oauth", "account", "identity", "saml"]):
        return "critical"
    if any(k in sub for k in ["api", "staging", "dev", "beta", "admin", "portal", "dashboard", "internal"]):
        return "high"
    return "medium"


def _is_external_location(location: str, target_url: str, base_domain: str) -> bool:
    if not location:
        return False
    try:
        normalized = urljoin(target_url, location)
        parsed = urlparse(normalized)
        host = (parsed.hostname or "").lower()
        if not host:
            return False
        return not (host == base_domain or host.endswith(f".{base_domain}"))
    except Exception:
        return False


def _probe_subdomain_http(subdomain: str) -> dict:
    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{subdomain}",
                timeout=8,
                verify=False,
                allow_redirects=True,
                headers=HEADERS,
            )
            return {"code": r.status_code, "body": r.text[:4000], "scheme": scheme}
        except requests.exceptions.ConnectionError:
            return {"code": 0, "body": "", "scheme": scheme}
        except requests.exceptions.Timeout:
            return {"code": -1, "body": "", "scheme": scheme}
        except Exception:
            continue
    return {"code": -1, "body": "", "scheme": "https"}


def _resolve_cname(subdomain: str):
    try:
        ans = TAKEOVER_RESOLVER.resolve(subdomain, "CNAME")
        return str(ans[0].target).rstrip(".")
    except Exception:
        return None


def _check_nxdomain(host: str) -> bool:
    try:
        TAKEOVER_RESOLVER.resolve(host, "A")
        return False
    except dns.resolver.NXDOMAIN:
        return True
    except dns.resolver.NoAnswer:
        return False
    except Exception:
        return False


def _dns_brute(target: str) -> list:
    wordlist = [
        "www", "mail", "blog", "api", "app", "dev", "staging", "test", "beta", "alpha",
        "admin", "portal", "support", "help", "docs", "status", "cdn", "static", "assets",
        "img", "media", "upload", "downloads", "shop", "store", "pay", "checkout", "login",
        "auth", "sso", "oauth", "account", "dashboard", "panel", "console", "manage", "demo",
        "preview", "sandbox", "qa", "uat", "prod", "internal", "git", "jira", "wiki", "kb",
        "forum", "community", "jobs", "careers", "press", "news", "events", "brand", "email",
        "newsletter", "crm", "analytics", "monitor", "search", "old", "legacy", "v1", "v2",
        "v3", "new", "next", "mobile", "m", "api2", "data", "cloud", "infra", "ops", "ci",
        "build", "deploy", "relay", "track", "link", "redirect", "partners", "developers",
        "affiliate", "ftp", "smtp", "vpn", "remote", "graphql", "grpc", "ws", "websocket",
        "proxy", "gateway", "edge", "origin", "vault", "secrets", "config", "db", "database",
        "keycloak", "sentry", "grafana", "kibana", "jenkins", "sonar", "nexus", "artifactory",
        "unsubscribe", "feedback", "survey", "checkout", "payment", "billing", "invoice",
    ]
    results = []
    for word in wordlist:
        sub = f"{word}.{target}"
        try:
            socket.getaddrinfo(sub, None, socket.AF_INET)
            results.append(sub)
        except Exception:
            pass
    return results


def _enumerate_subdomains(domain: str) -> tuple[list, list]:
    collected = set()
    logs = []

    # crt.sh passive cert enumeration
    logs.append("Trying crt.sh passive certificate enumeration...")
    try:
        crt = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            timeout=20,
            headers=HEADERS,
        )
        if crt.ok:
            entries = crt.json()
            for entry in entries[:5000]:
                names = str(entry.get("name_value", "")).splitlines()
                for name in names:
                    candidate = name.strip().lower().lstrip("*.").rstrip(".")
                    if candidate.endswith(f".{domain}") or candidate == domain:
                        collected.add(candidate)
            logs.append(f"crt.sh: {len(collected)} candidates")
    except Exception as e:
        logs.append(f"[WARN] crt.sh failed: {e}")

    # External tools
    tool_commands = []
    for tool, cmd_fn in [
        ("subfinder", lambda: [_resolve_tool_path("subfinder"), "-d", domain, "-silent"]),
        ("assetfinder", lambda: [_resolve_tool_path("assetfinder"), "--subs-only", domain]),
        ("amass", lambda: [_resolve_tool_path("amass"), "enum", "-passive", "-d", domain]),
    ]:
        path = _resolve_tool_path(tool)
        if path:
            tool_commands.append((tool, cmd_fn()))
        else:
            logs.append(f"[WARN] {tool} not found")

    for label, command in tool_commands:
        logs.append(f"Running {label}...")
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            lines = [l.strip().lower() for l in result.stdout.splitlines() if l.strip()]
            before = len(collected)
            for line in lines:
                if line.endswith(domain):
                    collected.add(line)
            logs.append(f"{label}: +{len(collected) - before} new subdomains")
        except subprocess.TimeoutExpired:
            logs.append(f"[WARN] {label} timed out")
        except Exception as e:
            logs.append(f"[WARN] {label} failed: {e}")

    # DNS brute force fallback
    brute = _dns_brute(domain)
    collected.update(brute)
    logs.append(f"DNS brute: {len(brute)} hits")

    return sorted(collected), logs


# ── Burp Import ───────────────────────────────────────────────────────────────

def _parse_burp_issue(issue: dict) -> dict | None:
    try:
        host = issue.get("host", "")
        url = issue.get("url", "")
        path = issue.get("path", "")
        severity = issue.get("severity", "info").lower()
        confidence = issue.get("confidence", "certain").lower()
        issue_name = issue.get("issueName", "")
        issue_detail = issue.get("issueDetail", "")
        issue_background = issue.get("issueBackground", "")
        remediation = issue.get("remediationBackground", "")
        request = issue.get("request", "")
        response = issue.get("response", "")

        severity_map = {
            "high": "high", "medium": "medium",
            "low": "low", "information": "info", "info": "info",
        }
        internal_severity = severity_map.get(severity, "info")

        if internal_severity not in ["critical", "high"]:
            return None

        asset = url or f"https://{host}{path}"
        if not _validate_url(asset):
            return None

        finding_title = issue_name or "Burp Suite Finding"
        details = f"Severity: {severity}; Confidence: {confidence}\n\n{issue_detail}"
        if issue_background:
            details += f"\n\nBackground: {issue_background}"
        if remediation:
            details += f"\n\nRemediation: {remediation}"

        evidence = json.dumps({
            "request": request,
            "response": response[:2000] if response else "",
        })

        vulnerable_objects = json.dumps([{
            "url": asset, "type": "endpoint", "description": finding_title,
        }])

        h1_report = (
            f"## {finding_title}\n\n"
            f"**Summary:**\n{issue_detail}\n\n"
            f"**Steps to Reproduce:**\n1. Send the following request:\n```\n{request}\n```\n\n"
            f"**Expected Response:**\n```\n{response[:500] if response else 'N/A'}\n```\n\n"
            f"**Impact:**\n{issue_background}\n\n"
            f"**Remediation:**\n{remediation}"
        )

        cve = issue.get("cve")
        if cve:
            h1_report = h1_report.replace("**Summary:**", f"**CVE:** {cve}\n\n**Summary:**")

        result = {
            "asset": asset,
            "finding": finding_title,
            "severity": internal_severity,
            "details": details,
            "evidence": evidence,
            "vulnerable_objects": vulnerable_objects,
            "h1_report": h1_report,
        }

        if not validate_hackerone_finding(result):
            return None

        return result
    except Exception as e:
        logger.exception(f"Failed to parse Burp issue: {e}")
        return None


# ── HackerOne Validation ──────────────────────────────────────────────────────

def validate_hackerone_finding(finding: dict) -> bool:
    """Validate finding against HackerOne submission requirements."""
    try:
        severity = finding.get("severity", "").lower()
        if severity not in ["critical", "high"]:
            return False

        asset = finding.get("asset", "")
        # Accept both URLs and bare domains (for DNS-based findings)
        if not asset:
            return False
        if not _validate_url(asset) and not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?$', asset):
            return False

        finding_title = finding.get("finding", "")
        details = finding.get("details", "")
        if not finding_title or not details or len(details) < 10:
            return False

        h1_report = finding.get("h1_report", "")
        if not h1_report or "Steps to Reproduce" not in h1_report or len(h1_report) < 50:
            return False

        # Must have vulnerable objects
        vuln_objs_raw = finding.get("vulnerable_objects", "[]")
        try:
            vuln_objs = json.loads(vuln_objs_raw) if isinstance(vuln_objs_raw, str) else vuln_objs_raw
        except Exception:
            return False

        if not isinstance(vuln_objs, list) or len(vuln_objs) == 0:
            return False

        # PoC check — relaxed to accept DNS-based findings too
        has_poc = any(marker in h1_report.lower() for marker in [
            "```", "curl", "dig ", "steps to reproduce", "payload", "request", "nxdomain",
        ])
        if not has_poc:
            return False

        return True
    except Exception:
        return False


# ── Nuclei Helpers ────────────────────────────────────────────────────────────

def _check_nuclei_version(nuclei_path: str) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            [nuclei_path, "-version"],
            capture_output=True, text=True, timeout=10,
        )
        output = result.stdout.strip() + result.stderr.strip()
        match = re.search(r'(\d+)\.(\d+)\.(\d+)', output)
        if not match:
            return False, f"Could not parse version from: {output[:100]}"
        major, minor, patch = map(int, match.groups())
        if major >= 3:
            return True, f"v{major}.{minor}.{patch}"
        return False, f"v{major}.{minor}.{patch} is too old (need v3+)"
    except Exception as e:
        return False, f"Error: {e}"


def _validate_nuclei_target(target: str) -> tuple[bool, str, list]:
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string", []

    target = target.strip()

    if target.startswith("[") and target.endswith("]"):
        try:
            subdomains = json.loads(target)
            if not isinstance(subdomains, list) or not subdomains:
                return False, "Target list must be a non-empty JSON array", []
            if len(subdomains) > MAX_SUBDOMAIN_LIST_SIZE:
                return False, f"List exceeds max size of {MAX_SUBDOMAIN_LIST_SIZE}", []
            normalized = []
            for sub in subdomains:
                if not isinstance(sub, str):
                    continue
                d = _as_domain(sub)
                if d:
                    normalized.append(d)
            if not normalized:
                return False, "No valid domains in list", []
            return True, f"Validated {len(normalized)} subdomains", normalized
        except json.JSONDecodeError:
            return False, "Invalid JSON format for subdomain list", []

    domain = _as_domain(target)
    if not domain:
        return False, f"Invalid domain format: {target}", []
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', domain):
        return False, f"Domain contains invalid characters: {domain}", []
    return True, f"Validated: {domain}", [domain]


def _parse_nuclei_finding(data: dict, fallback_url: str = "") -> dict | None:
    try:
        if not isinstance(data, dict):
            return None

        template_id = str(data.get("template-id", "")).strip()
        if not template_id:
            return None

        info = data.get("info", {})
        if not isinstance(info, dict):
            return None

        severity = str(data.get("severity", info.get("severity", "info"))).lower().strip()
        severity_map = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}
        internal_severity = severity_map.get(severity, "info")

        if internal_severity not in ["critical", "high"]:
            return None

        url = str(data.get("matched-at", data.get("url", ""))).strip()
        asset = url or fallback_url
        if not asset or not _validate_url(asset):
            return None

        name = str(info.get("name", template_id)).strip() or template_id
        finding_title = f"Nuclei: {name}"

        details = f"Template: {template_id}\nSeverity: {severity}\n"
        description = str(info.get("description", "")).strip()
        if description:
            details += f"Description: {description}\n"

        tags = info.get("tags", [])
        if isinstance(tags, list):
            tag_strs = [str(t).strip() for t in tags if str(t).strip()]
            if tag_strs:
                details += f"Tags: {', '.join(tag_strs)}\n"

        extracted = data.get("extracted-results", [])
        if isinstance(extracted, list) and extracted:
            valid_ex = [str(r).strip() for r in extracted if str(r).strip()]
            if valid_ex:
                details += f"Extracted: {json.dumps(valid_ex)}\n"

        curl_command = str(data.get("curl-command", "")).strip()
        evidence = json.dumps({"nuclei_data": data, "curl_command": curl_command})
        vulnerable_objects = json.dumps([{"url": asset, "type": "endpoint", "description": finding_title}])

        h1_report = f"## {finding_title}\n\n**Summary:**\n{description or 'Nuclei detected a vulnerability.'}\n\n"

        classification = info.get("classification", {})
        if isinstance(classification, dict):
            cve_id = str(classification.get("cve-id", "")).strip()
            if cve_id and re.match(r'^CVE-\d{4}-\d{4,}$', cve_id):
                h1_report += f"**CVE:** {cve_id}\n\n"

        h1_report += f"**Affected URL:**\n{asset}\n\n"
        if curl_command:
            h1_report += f"**Steps to Reproduce:**\n```bash\n{curl_command}\n```\n\n"
        else:
            h1_report += f"**Steps to Reproduce:**\n1. Visit: {asset}\n\n"

        if isinstance(extracted, list) and extracted:
            ex_strs = [str(r).strip() for r in extracted if str(r).strip()]
            if ex_strs:
                h1_report += f"**Extracted Data:**\n```\n{chr(10).join(ex_strs)}\n```\n\n"

        impact = str(info.get("impact", "")).strip()
        remediation = str(info.get("remediation", "")).strip()
        h1_report += (
            f"**Impact:**\n{impact or 'See description'}\n\n"
            f"**Remediation:**\n{remediation or 'Fix the underlying vulnerability.'}"
        )

        result = {
            "asset": asset,
            "finding": finding_title,
            "severity": internal_severity,
            "details": details,
            "evidence": evidence,
            "vulnerable_objects": vulnerable_objects,
            "h1_report": h1_report,
        }

        if not validate_hackerone_finding(result):
            return None

        return result
    except Exception as e:
        logger.debug(f"_parse_nuclei_finding error: {e}")
        return None


# ── Scanner: Subdomain Takeover ───────────────────────────────────────────────

def scan_subdomain_takeover(target: str, options: dict):
    domain = _as_domain(target)
    if not domain:
        yield log("[ERROR] Invalid target")
        return

    yield log(f"Starting subdomain takeover scan on {domain}")
    subdomains, enum_logs = _enumerate_subdomains(domain)
    for msg in enum_logs:
        yield log(msg)

    if not subdomains:
        yield log("No subdomains found — cannot continue")
        return

    yield log(f"Total subdomains: {len(subdomains)}")

    cname_records = []
    for sub in subdomains:
        cname_target = _resolve_cname(sub)
        if cname_target:
            fp = _get_fingerprint(cname_target)
            cname_records.append({
                "sub": sub, "cname": cname_target,
                "provider": fp["provider"] if fp else "Unknown", "fp": fp,
            })

    yield log(f"CNAME candidates: {len(cname_records)} of {len(subdomains)}")
    if not cname_records:
        yield log("No CNAME candidates — no takeover vectors found")
        return

    for record in cname_records:
        sub, cname_target, fp = record["sub"], record["cname"], record["fp"]
        provider = record["provider"]
        yield log(f"Checking {sub} → {cname_target} ({provider})")

        probe = _probe_subdomain_http(sub)
        nxdomain = _check_nxdomain(cname_target)

        body_match = False
        match_string = None
        if fp and fp.get("status_match") and probe["body"]:
            if fp["status_match"].lower() in probe["body"].lower():
                body_match = True
                match_string = fp["status_match"]

        vulnerable = False
        confidence = "low"
        if nxdomain and probe["code"] in (0, -1):
            vulnerable, confidence = True, "high"
        elif nxdomain and body_match:
            vulnerable, confidence = True, "high"
        elif body_match and fp and fp.get("takeover"):
            vulnerable, confidence = True, "medium"
        elif nxdomain and fp and fp.get("takeover"):
            vulnerable, confidence = True, "medium"

        if vulnerable:
            severity = _takeover_severity(sub)
            detail = (
                f"CNAME={cname_target}; HTTP={probe['code']}; "
                f"NXDOMAIN={str(nxdomain).lower()}; confidence={confidence}"
            )
            if match_string:
                detail += f"; fingerprint_match={match_string}"
            yield _make_finding(
                sub, detail, severity,
                f"Subdomain takeover via {provider} on {sub} ({confidence} confidence)",
                _takeover_report(sub, cname_target, provider),
                module="subdomain-takeover",
            )

    yield log("Subdomain takeover scan complete.")


# ── Guided Takeover Workflow ──────────────────────────────────────────────────

def takeover_enumerate(target: str) -> dict:
    domain = _as_domain(target)
    if not domain:
        return {"target": target, "subdomains": [], "logs": ["[ERROR] Invalid target"]}
    subdomains, logs = _enumerate_subdomains(domain)
    return {"target": domain, "subdomains": subdomains, "logs": logs}


def takeover_triage(subdomains: list) -> dict:
    results = {"cname": [], "a": [], "dead": []}
    for sub in subdomains:
        cname = _resolve_cname(sub)
        if cname:
            fp = _get_fingerprint(cname)
            results["cname"].append({
                "sub": sub, "cname": cname,
                "provider": fp["provider"] if fp else "Unknown", "fp": fp,
            })
            continue
        try:
            ans = TAKEOVER_RESOLVER.resolve(sub, "A")
            results["a"].append({"sub": sub, "ips": [str(r) for r in ans]})
        except Exception:
            results["dead"].append({"sub": sub})
    return results


def takeover_scan_cnames(cname_records: list) -> dict:
    vulnerabilities = []
    logs = []

    records = []
    for record in cname_records:
        if isinstance(record, dict):
            records.append(record)
        elif isinstance(record, str):
            sub = record.strip()
            if sub:
                cname_target = _resolve_cname(sub)
                if cname_target:
                    fp = _get_fingerprint(cname_target)
                    records.append({
                        "sub": sub, "cname": cname_target, "fp": fp,
                        "provider": fp["provider"] if fp else _detect_provider(cname_target),
                    })

    for record in records:
        sub = record.get("sub", "")
        cname_target = record.get("cname", "")
        fp = record.get("fp")
        provider = record.get("provider") or (fp["provider"] if fp else _detect_provider(cname_target))
        logs.append(f"Scanning {sub} → {cname_target} ({provider})")

        probe = _probe_subdomain_http(sub)
        nxdomain = _check_nxdomain(cname_target)

        body_match = False
        match_string = None
        if fp and fp.get("status_match") and probe["body"]:
            if fp["status_match"].lower() in probe["body"].lower():
                body_match = True
                match_string = fp["status_match"]

        vulnerable = False
        confidence = "low"
        if nxdomain and probe["code"] in (0, -1):
            vulnerable, confidence = True, "high"
        elif nxdomain and body_match:
            vulnerable, confidence = True, "high"
        elif body_match and fp and fp.get("takeover"):
            vulnerable, confidence = True, "medium"
        elif nxdomain and fp and fp.get("takeover"):
            vulnerable, confidence = True, "medium"

        if vulnerable:
            vulnerabilities.append({
                "sub": sub, "cname": cname_target, "provider": provider,
                "nxdomain": nxdomain, "http_code": probe["code"],
                "body_match": body_match, "match_string": match_string,
                "confidence": confidence, "severity": _takeover_severity(sub),
            })

    return {"vulnerable": vulnerabilities, "logs": logs}


def takeover_verify(vulnerable_list: list) -> dict:
    """Double-pass NXDOMAIN verification run concurrently."""
    verified = []
    logs = []

    def _verify_one(item: dict) -> dict:
        sub = item.get("sub", "")
        cname = item.get("cname", "")
        nxdomain_1 = _check_nxdomain(cname)
        nxdomain_2 = _check_nxdomain(cname)
        probe = _probe_subdomain_http(sub)
        cname_check = _resolve_cname(sub)
        is_confirmed = (
            bool(cname_check) and
            (cname_check == cname or cname in cname_check) and
            (nxdomain_1 or nxdomain_2) and
            probe["code"] in (0, 404, -1)
        )
        return {
            **item,
            "verify_nxdomain_1": nxdomain_1,
            "verify_nxdomain_2": nxdomain_2,
            "verify_http": probe["code"],
            "cname_still_present": bool(cname_check),
            "verified": is_confirmed,
        }

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(_verify_one, item): item for item in vulnerable_list}
        for fut in as_completed(futures):
            try:
                result = fut.result(timeout=30)
                verified.append(result)
                logs.append(f"Verified {result['sub']}: {'✓' if result['verified'] else '✗'}")
            except Exception as e:
                item = futures[fut]
                logs.append(f"[WARN] Verify failed for {item.get('sub', '?')}: {e}")

    return {"verified": verified, "logs": logs}


# ── Scanner: S3 / Blob Buckets ────────────────────────────────────────────────

def scan_s3_buckets(target: str, options: dict):
    yield log(f"Scanning S3/Blob buckets for {target}")
    domain = _as_domain(target)
    if not domain:
        yield log("[ERROR] Invalid target")
        return
    name = domain.split(".")[0]

    candidates = [
        name, f"{name}-backup", f"{name}-dev", f"{name}-staging",
        f"{name}-prod", f"{name}-assets", f"{name}-static", f"{name}-media",
        f"{name}-uploads", f"{name}-data", f"www-{name}", f"api-{name}",
        f"{name}-public", f"{name}-private", f"{name}-files", f"{name}-images",
    ]

    for bucket in candidates:
        # AWS S3
        s3_url = f"https://{bucket}.s3.amazonaws.com"
        yield log(f"Checking {s3_url}")
        try:
            r = requests.get(s3_url, headers=HEADERS, timeout=8)
            if r.status_code == 200 and "<ListBucketResult" in r.text:
                yield _make_finding(
                    s3_url, bucket, "critical",
                    "Public S3 bucket — directory listing exposed",
                    _bucket_report(s3_url, "AWS S3", "public listing"),
                    module="s3-buckets",
                )
            elif "NoSuchBucket" in r.text:
                yield log(f"{bucket} — NoSuchBucket (S3)")
            elif r.status_code == 403:
                yield log(f"{bucket} — exists but access denied (403), not flagged")
        except Exception as e:
            yield log(f"[ERR] S3 {bucket}: {e}")

        # Azure Blob — only flag 200 with container listing, not bare 400
        az_url = f"https://{bucket}.blob.core.windows.net/{bucket}?restype=container&comp=list"
        try:
            r = requests.get(az_url, headers=HEADERS, timeout=8)
            if r.status_code == 200 and "<EnumerationResults" in r.text:
                yield _make_finding(
                    az_url, bucket, "high",
                    "Azure Blob container — public listing exposed",
                    _bucket_report(az_url, "Azure Blob", "public listing"),
                    module="s3-buckets",
                )
        except Exception:
            pass

    yield log("Bucket scan complete.")


# ── Scanner: CORS ─────────────────────────────────────────────────────────────

def scan_cors(target: str, options: dict):
    target_url = _as_url(target)
    target_host = _as_domain(target)
    if not target_url or not target_host:
        yield log("[ERROR] Invalid target")
        return

    yield log(f"Scanning CORS on {target_url}")
    evil_origins = [
        "https://evil.com",
        f"https://evil.{target_host}",
        f"https://{target_host}.evil.com",
        "null",
        "https://attacker.com",
    ]

    for origin in evil_origins:
        yield log(f"Testing Origin: {origin}")
        try:
            r = requests.get(
                target_url,
                headers={**HEADERS, "Origin": origin},
                timeout=8,
            )
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao in (origin, "*") or (acao and origin in acao):
                sev = "high" if acac.lower() == "true" else "medium"
                yield _make_finding(
                    target_url,
                    f"ACAO: {acao}; ACAC: {acac}; Test origin: {origin}",
                    sev,
                    f"CORS reflects arbitrary origin (credentials={'yes' if acac.lower() == 'true' else 'no'})",
                    _cors_report(target_url, origin, acao, acac),
                    module="cors",
                )
        except Exception as e:
            yield log(f"[ERR] CORS {origin}: {e}")

    yield log("CORS scan complete.")


# ── Scanner: Sensitive Files ──────────────────────────────────────────────────

def scan_sensitive_files(target: str, options: dict):
    base = _as_url(target).rstrip("/")
    if not base:
        yield log("[ERROR] Invalid target")
        return

    yield log(f"Scanning sensitive file exposure on {base}")
    max_workers = min(20, (os.cpu_count() or 1) + 4)
    request_timeout = max(MIN_REQUEST_TIMEOUT, min(options.get("timeout", 8), MAX_REQUEST_TIMEOUT))

    def check(path: str):
        url = base + path
        try:
            r = requests.get(
                url, headers=HEADERS,
                timeout=request_timeout,
                allow_redirects=False,
            )
            if r.status_code == 200 and len(r.content) > 0:
                return url, r.status_code, len(r.content)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(check, p): p for p in SENSITIVE_PATHS}
        for fut in as_completed(futures):
            try:
                result = fut.result(timeout=request_timeout + 5)
                if result:
                    url, code, size = result
                    yield log(f"⚠️  EXPOSED: {url} ({code}, {size}b)")
                    yield _make_finding(
                        url,
                        f"HTTP {code}, {size} bytes returned for {futures[fut]}",
                        "high",
                        f"Sensitive file exposed: {futures[fut]}",
                        _sensitive_report(url),
                        module="sensitive-files",
                    )
            except Exception as e:
                yield log(f"[ERR] check failed: {e}")

    yield log("Sensitive file scan complete.")


# ── Scanner: API Key Leak ─────────────────────────────────────────────────────

def scan_api_key_leak(target: str, options: dict):
    target_url = _as_url(target)
    if not target_url:
        yield log("[ERROR] Invalid target")
        return

    yield log(f"Scanning for API key leaks in JS on {target_url}")
    patterns = {
        "AWS Access Key":   r"AKIA[0-9A-Z]{16}",
        "Google API Key":   r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe Secret":    r"sk_live_[0-9a-zA-Z]{24}",
        "Stripe Public":    r"pk_live_[0-9a-zA-Z]{24}",
        "GitHub Token":     r"ghp_[0-9a-zA-Z]{36}",
        "GitHub Fine-grained": r"github_pat_[0-9a-zA-Z_]{82}",
        "Slack Token":      r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
        "Private Key":      r"-----BEGIN (?:RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
        "Bearer Token":     r"Bearer [a-zA-Z0-9\-._~+/]{20,}",
        "JWT":              r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
        "Twilio SID":       r"AC[a-zA-Z0-9]{32}",
        "SendGrid Key":     r"SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}",
        "Firebase URL":     r"https://[a-zA-Z0-9\-]+\.firebaseio\.com",
        "Mailchimp Key":    r"[0-9a-f]{32}-us[0-9]{1,2}",
    }

    try:
        r = requests.get(target_url, headers=HEADERS, timeout=10)
        js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', r.text)
        js_urls = list(set(urljoin(target_url, u) for u in js_urls))
    except Exception as e:
        yield log(f"[ERR] Fetching target: {e}")
        return

    yield log(f"Found {len(js_urls)} JS files to scan")

    for js_url in js_urls[:50]:
        yield log(f"Scanning {js_url}")
        try:
            r = requests.get(js_url, headers=HEADERS, timeout=10)
            for key_type, pattern in patterns.items():
                matches = re.findall(pattern, r.text)
                for match in matches:
                    yield _make_finding(
                        js_url,
                        f"Pattern: {key_type}; Match: {match[:40]}...",
                        "critical",
                        f"{key_type} exposed in JavaScript file",
                        _apikey_report(js_url, key_type, match),
                        module="api-key-leak",
                    )
        except Exception as e:
            yield log(f"[ERR] {js_url}: {e}")

    yield log("API key leak scan complete.")


# ── Scanner: Open Redirect ────────────────────────────────────────────────────

def scan_open_redirect(target: str, options: dict):
    target_url = _as_url(target)
    if not target_url:
        yield log("[ERROR] Invalid target")
        return
    if _should_skip_domain(target):
        yield log(f"[SKIP] {target} — known hardened domain")
        return

    yield log(f"Scanning open redirects on {target_url}")
    target_host = (urlparse(target_url).hostname or "").lower()
    base_domain = _base_domain(target_host)
    payload = "https://evil.com"

    for param in REDIRECT_PARAMS:
        separator = "&" if "?" in target_url else "?"
        url = f"{target_url}{separator}{param}={payload}"
        yield log(f"Testing ?{param}=")
        try:
            r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=False)
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 303, 307, 308) and _is_external_location(loc, target_url, base_domain):
                yield _make_finding(
                    url,
                    f"Parameter '{param}' redirects to {loc}",
                    "medium",
                    f"Open redirect via '{param}' → {loc}",
                    _redirect_report(url, param, loc),
                    module="open-redirect",
                )
        except Exception as e:
            yield log(f"[ERR] {e}")

    yield log("Open redirect scan complete.")


# ── Scanner: Clickjacking ─────────────────────────────────────────────────────

def scan_clickjacking(target: str, options: dict):
    target_url = _as_url(target)
    if not target_url:
        yield log("[ERROR] Invalid target")
        return

    yield log(f"Scanning clickjacking headers on {target_url}")
    try:
        r = requests.get(target_url, headers=HEADERS, timeout=10)
        xfo = r.headers.get("X-Frame-Options", "")
        csp = r.headers.get("Content-Security-Policy", "")
        has_frame_guard = bool(xfo) or "frame-ancestors" in csp.lower()

        if not has_frame_guard:
            yield _make_finding(
                target_url,
                f"X-Frame-Options: absent; CSP frame-ancestors: absent",
                "medium",
                "Missing clickjacking protection (X-Frame-Options / CSP frame-ancestors)",
                _clickjack_report(target_url),
                module="clickjacking",
            )
        else:
            yield log(f"Protected — XFO: '{xfo}', CSP frame-ancestors: {bool('frame-ancestors' in csp.lower())}")
    except Exception as e:
        yield log(f"[ERR] {e}")

    yield log("Clickjacking scan complete.")


# ── Scanner: DNS Zone Transfer ────────────────────────────────────────────────

def scan_dns_zone_transfer(target: str, options: dict):
    domain = _as_domain(target)
    if not domain:
        yield log("[ERROR] Invalid target")
        return

    yield log(f"Attempting DNS zone transfer on {domain}")
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
    except Exception as e:
        yield log(f"[ERR] NS lookup failed: {e}")
        return

    for ns in ns_answers:
        ns_str = str(ns).rstrip(".")
        yield log(f"Trying AXFR on {ns_str}")
        try:
            zone = dns.query.xfr(ns_str, domain, timeout=10)
            z = dns.zone.from_xfr(zone)
            records = [str(n) for n in z.nodes.keys()]
            yield _make_finding(
                domain,
                f"Nameserver: {ns_str}; Records: {len(records)}",
                "high",
                f"DNS zone transfer allowed — {len(records)} records exposed via {ns_str}",
                _zone_transfer_report(domain, ns_str, records),
                module="dns-zone-transfer",
            )
        except Exception as e:
            yield log(f"{ns_str} — refused: {type(e).__name__}")

    yield log("Zone transfer scan complete.")


# ── Scanner: SPF / DMARC ──────────────────────────────────────────────────────

def scan_spf_dmarc(target: str, options: dict):
    domain = _as_domain(target)
    if not domain:
        yield log("[ERROR] Invalid target")
        return

    yield log(f"Checking SPF/DMARC for {domain}")

    # SPF
    try:
        txt = dns.resolver.resolve(domain, "TXT")
        spf_records = [r.to_text().strip('"') for r in txt if "v=spf1" in r.to_text().lower()]
        if not spf_records:
            yield _make_finding(
                domain, "No SPF TXT record found", "medium",
                "Missing SPF record — email spoofing possible",
                _email_spoof_report(domain, "SPF missing"),
                module="spf-dmarc",
            )
        else:
            yield log(f"SPF: {spf_records[0][:100]}")
            if "+all" in spf_records[0]:
                yield _make_finding(
                    domain, f"SPF record: {spf_records[0]}", "high",
                    "SPF uses +all — any sender accepted",
                    _email_spoof_report(domain, "SPF +all"),
                    module="spf-dmarc",
                )
    except Exception as e:
        yield log(f"[ERR] SPF lookup: {e}")

    # DMARC
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        records = [r.to_text().strip('"') for r in dmarc]
        if not records:
            yield _make_finding(
                domain, "No DMARC TXT record at _dmarc." + domain, "medium",
                "Missing DMARC record — email spoofing not mitigated",
                _email_spoof_report(domain, "DMARC missing"),
                module="spf-dmarc",
            )
        else:
            yield log(f"DMARC: {records[0][:100]}")
            if "p=none" in records[0].lower():
                yield _make_finding(
                    domain, f"DMARC: {records[0]}", "low",
                    "DMARC policy p=none — monitoring only, no enforcement",
                    _email_spoof_report(domain, "DMARC p=none"),
                    module="spf-dmarc",
                )
    except dns.resolver.NXDOMAIN:
        yield _make_finding(
            domain, "_dmarc subdomain does not exist", "medium",
            "Missing DMARC record — email spoofing not mitigated",
            _email_spoof_report(domain, "DMARC missing"),
            module="spf-dmarc",
        )
    except Exception as e:
        yield log(f"[ERR] DMARC lookup: {e}")

    yield log("SPF/DMARC scan complete.")


# ── Scanner: Rate Limit ───────────────────────────────────────────────────────

def scan_rate_limit(target: str, options: dict):
    target_url = _as_url(target)
    if not target_url:
        yield log("[ERROR] Invalid target")
        return
    if _should_skip_domain(target):
        yield log(f"[SKIP] {target} — known hardened domain")
        return

    yield log(f"Testing rate limiting on {target_url}")
    count = int(options.get("requests", 30))
    codes = []

    for i in range(count):
        try:
            r = requests.post(
                target_url,
                json={"test": i},
                headers=HEADERS,
                timeout=5,
            )
            codes.append(r.status_code)
            yield log(f"Request {i+1}: {r.status_code}")
            if r.status_code == 429:
                break
        except Exception as e:
            yield log(f"[ERR] Request {i+1}: {e}")

    if not codes:
        yield log("Rate limit test inconclusive — no HTTP responses")
    elif all(c in {401, 403, 404, 405} for c in codes):
        yield log(f"Inconclusive — endpoint blocked ({set(codes)})")
    elif 429 not in codes:
        yield _make_finding(
            target_url,
            f"{count} requests sent, codes: {sorted(set(codes))}",
            "medium",
            f"No rate limiting detected after {count} requests",
            _ratelimit_report(target_url, count),
            module="rate-limit",
        )
    else:
        idx = codes.index(429)
        yield log(f"Rate limiting active — 429 after {idx + 1} requests")

    yield log("Rate limit scan complete.")


# ── Scanner: Nuclei ───────────────────────────────────────────────────────────

def scan_nuclei(target: str, options: dict):
    yield log("[NUCLEI] Starting nuclei vulnerability scan pipeline")

    is_valid, validation_msg, target_list = _validate_nuclei_target(target)
    if not is_valid:
        yield log(f"[NUCLEI ERROR] {validation_msg}")
        return
    yield log(f"[NUCLEI] {validation_msg}")

    nuclei_path = _resolve_tool_path("nuclei")
    if not nuclei_path:
        local = Path.cwd() / "nuclei.exe"
        if local.exists():
            nuclei_path = str(local)
        else:
            yield log("[NUCLEI ERROR] nuclei binary not found — install from https://github.com/projectdiscovery/nuclei")
            return
    yield log(f"[NUCLEI] Binary: {nuclei_path}")

    version_ok, version_msg = _check_nuclei_version(nuclei_path)
    if not version_ok:
        yield log(f"[NUCLEI ERROR] Version check: {version_msg}")
        return
    yield log(f"[NUCLEI] Version: {version_msg}")

    total_findings = 0

    for i, domain in enumerate(target_list, 1):
        target_url = f"https://{domain}"
        yield log(f"[NUCLEI] Target {i}/{len(target_list)}: {target_url}")

        timeout_s = int(options.get("timeout", 30))
        rate_limit = int(options.get("rate-limit", 10))
        templates = str(options.get("templates", "")).strip()

        cmd = [
            nuclei_path,
            "-u", target_url,
            "-jsonl",
            "-silent",
            "-no-interactsh",
            "-timeout", str(timeout_s),
            "-severity", "critical,high",
            "-rate-limit", str(rate_limit),
        ]
        if templates:
            cmd.extend(["-t", templates])

        yield log(f"[NUCLEI] CMD: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=int(options.get("process_timeout", 600)),
            )

            if result.returncode not in (0, 2):
                yield log(f"[NUCLEI ERROR] Exit code {result.returncode}: {result.stderr[:200]}")
                continue

            if result.returncode == 2:
                yield log(f"[NUCLEI WARN] Exit code 2 (template warnings): {result.stderr[:100]}")

            stdout = result.stdout.strip()
            if not stdout:
                yield log(f"[NUCLEI] No findings on {target_url}")
                continue

            target_count = 0
            for line_num, line in enumerate(stdout.splitlines(), 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    finding_data = json.loads(line)
                except json.JSONDecodeError as e:
                    yield log(f"[NUCLEI ERROR] JSON parse line {line_num}: {e}")
                    continue

                parsed = _parse_nuclei_finding(finding_data, target_url)
                if parsed:
                    yield {
                        "type": "finding",
                        "data": parsed,
                    }
                    target_count += 1
                    total_findings += 1
                else:
                    yield log(f"[NUCLEI] Filtered: {finding_data.get('template-id', 'unknown')}")

            yield log(f"[NUCLEI] {target_url} — {target_count} findings")

        except subprocess.TimeoutExpired:
            yield log(f"[NUCLEI ERROR] Timed out on {target_url}")
        except FileNotFoundError:
            yield log(f"[NUCLEI ERROR] Binary not found at {nuclei_path}")
        except PermissionError:
            yield log(f"[NUCLEI ERROR] Permission denied: {nuclei_path}")
        except Exception as e:
            yield log(f"[NUCLEI ERROR] {type(e).__name__}: {e}")

    yield log(f"[NUCLEI] Pipeline complete — {total_findings} total findings")


# ── Report Templates ──────────────────────────────────────────────────────────

def _takeover_report(sub, cname, provider):
    return (
        f"## Subdomain Takeover via Dangling {provider} CNAME on {sub}\n\n"
        f"**Summary:**\n"
        f"{sub} has a dangling CNAME record pointing to a deprovisioned {provider} "
        f"resource ({cname}).\n\n"
        f"**Steps to Reproduce:**\n"
        f"```bash\n"
        f"dig {sub} CNAME +noall +answer\n"
        f"dig @8.8.8.8 {cname}  # expect NXDOMAIN\n"
        f"curl -sk -o /dev/null -w \"%{{http_code}}\" https://{sub}\n"
        f"```\n\n"
        f"**Impact:**\n"
        f"Attacker can claim `{cname}` on {provider} and serve arbitrary content "
        f"under `{sub}`, enabling phishing, session hijacking, or malware distribution.\n\n"
        f"**Header:** X-Bug-Bounty: HackerOne-stickybugger"
    )


def _bucket_report(url, provider, detail):
    return (
        f"## Exposed {provider} Bucket\n\n"
        f"**URL:** {url}\n"
        f"**Finding:** {detail}\n\n"
        f"**Steps to Reproduce:**\n"
        f"```bash\ncurl -sk \"{url}\"\n```\n\n"
        f"**Impact:** Data exposure, potential write access, brand abuse, GDPR violations."
    )


def _cors_report(target, origin, acao, acac):
    return (
        f"## CORS Misconfiguration on {target}\n\n"
        f"**Reflected Origin:** `{acao}`\n"
        f"**Credentials Allowed:** `{acac}`\n"
        f"**Test Origin:** `{origin}`\n\n"
        f"**Steps to Reproduce:**\n"
        f"```bash\ncurl -H \"Origin: {origin}\" -I {target}\n```\n\n"
        f"**Impact:** Cross-origin data theft"
        + (" including authenticated session data." if acac.lower() == "true" else ".")
    )


def _sensitive_report(url):
    return (
        f"## Sensitive File Exposed\n\n"
        f"**URL:** {url}\n\n"
        f"**Steps to Reproduce:**\n"
        f"```bash\ncurl -sk {url}\n```\n\n"
        f"**Impact:** Credential/config/source code exposure depending on file type."
    )


def _apikey_report(js_url, key_type, match):
    return (
        f"## {key_type} Exposed in JavaScript\n\n"
        f"**File:** {js_url}\n"
        f"**Match:** `{match[:40]}...`\n\n"
        f"**Steps to Reproduce:**\n"
        f"```bash\ncurl -sk {js_url} | grep -oE 'AKIA[0-9A-Z]{{16}}'\n```\n\n"
        f"**Impact:** Full account compromise depending on key permissions and service."
    )


def _redirect_report(url, param, location):
    return (
        f"## Open Redirect via `{param}` Parameter\n\n"
        f"**URL:** {url}\n"
        f"**Redirects to:** {location}\n\n"
        f"**Steps to Reproduce:**\n"
        f"```bash\ncurl -I \"{url}\"\n```\n\n"
        f"**Impact:** Phishing, OAuth token theft via redirect_uri manipulation."
    )


def _clickjack_report(target):
    return (
        f"## Clickjacking Vulnerability on {target}\n\n"
        f"**Missing:** X-Frame-Options and CSP frame-ancestors\n\n"
        f"**Steps to Reproduce:**\n"
        f"```html\n<iframe src=\"{target}\" width=\"800\" height=\"600\"></iframe>\n```\n\n"
        f"**Impact:** UI redressing attacks, forced clicks on authenticated actions."
    )


def _zone_transfer_report(target, ns, records):
    sample = ", ".join(records[:5])
    return (
        f"## DNS Zone Transfer Allowed on {target}\n\n"
        f"**Nameserver:** {ns}\n"
        f"**Records Exposed:** {len(records)}\n"
        f"**Sample:** {sample}\n\n"
        f"**Steps to Reproduce:**\n"
        f"```bash\ndig AXFR {target} @{ns}\n```\n\n"
        f"**Impact:** Full subdomain enumeration, internal infrastructure mapping."
    )


def _email_spoof_report(target, issue):
    return (
        f"## Email Spoofing via {issue} on {target}\n\n"
        f"**Issue:** {issue} misconfigured or missing\n\n"
        f"**Steps to Reproduce:**\n"
        f"```bash\ndig TXT {target}\ndig TXT _dmarc.{target}\n```\n\n"
        f"**Impact:** Attacker can send emails appearing to originate from @{target}."
    )


def _ratelimit_report(target, count):
    return (
        f"## Missing Rate Limiting on {target}\n\n"
        f"**Test:** {count} requests — no 429 received\n\n"
        f"**Steps to Reproduce:**\n"
        f"```bash\n"
        f"for i in $(seq 1 {count}); do\n"
        f"  curl -s -o /dev/null -w \"%{{http_code}}\\n\" -X POST {target}\n"
        f"done\n"
        f"```\n\n"
        f"**Impact:** Brute force on login, OTP, password reset, or API endpoints."
    )