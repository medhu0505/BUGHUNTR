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
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

logger = logging.getLogger(__name__)

# Configuration limits
MAX_SUBDOMAIN_LIST_SIZE = 1000
MAX_REQUEST_TIMEOUT = 120
MIN_REQUEST_TIMEOUT = 5
TAKEOVER_RESOLVER = dns.resolver.Resolver()
TAKEOVER_RESOLVER.nameservers = ["8.8.8.8", "1.1.1.1"]
TAKEOVER_RESOLVER.timeout = 3
TAKEOVER_RESOLVER.lifetime = 5
TAKEOVER_FINGERPRINTS = [
    {"provider": "Heroku", "patterns": ["herokudns.com", "herokuapp.com"], "takeover": True, "status_match": "No such app"},
    {"provider": "GitHub Pages", "patterns": ["github.io", "githubusercontent.com"], "takeover": True, "status_match": "There isn't a GitHub Pages site here"},
    {"provider": "AWS S3", "patterns": ["s3.amazonaws.com", "s3-website", "amazonaws.com"], "takeover": True, "status_match": "NoSuchBucket"},
    {"provider": "Azure", "patterns": ["azurewebsites.net", "cloudapp.net"], "takeover": True, "status_match": "404 Web Site not found"},
    {"provider": "Fastly", "patterns": ["fastly.net"], "takeover": True, "status_match": "Fastly error: unknown domain"},
    {"provider": "Netlify", "patterns": ["netlify.app", "netlify.com"], "takeover": True, "status_match": "Not Found"},
    {"provider": "Vercel", "patterns": ["vercel.app", "now.sh"], "takeover": True, "status_match": "The deployment could not be found"},
    {"provider": "Shopify", "patterns": ["myshopify.com", "shopify.com"], "takeover": True, "status_match": "Sorry, this shop is currently unavailable"},
    {"provider": "Tumblr", "patterns": ["tumblr.com"], "takeover": True, "status_match": "Whatever you were looking for doesn't currently exist"},
    {"provider": "WordPress", "patterns": ["wordpress.com", "wpengine.com"], "takeover": True, "status_match": "Do you want to register"},
    {"provider": "Typepad", "patterns": ["typepad.com"], "takeover": True, "status_match": "Domain is not configured"},
    {"provider": "Surge.sh", "patterns": ["surge.sh"], "takeover": True, "status_match": "project not found"},
    {"provider": "Ghost", "patterns": ["ghost.io"], "takeover": True, "status_match": "The thing you were looking for is no longer here"},
    {"provider": "Unbounce", "patterns": ["unbouncepages.com"], "takeover": True, "status_match": "The requested URL was not found"},
    {"provider": "StatusPage", "patterns": ["statuspage.io"], "takeover": True, "status_match": "Page Not Found"},
    {"provider": "Strikingly", "patterns": ["strikinglydns.com"], "takeover": True, "status_match": "page not found"},
    {"provider": "Webflow", "patterns": ["proxy.webflow.com", "webflow.io"], "takeover": True, "status_match": "The page you are looking for doesn't exist"},
    {"provider": "Fly.io", "patterns": ["fly.dev", "fly.io"], "takeover": True, "status_match": "404"},
]

SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/config.json", "/backup.zip",
    "/wp-config.php", "/debug.log", "/server-status", "/phpinfo.php",
    "/.DS_Store", "/credentials.json", "/secrets.yaml", "/api/swagger.json",
    "/.aws/credentials", "/config/database.yml",
]

REDIRECT_PARAMS = ["url", "next", "redirect", "redirect_uri", "return", "returnTo",
                   "goto", "destination", "continue", "forward"]

DMARC_REQUIRED = ["v=DMARC1"]
SPF_REQUIRED = ["v=spf1"]

# Domains to skip for vulnerability testing (known safe/hardened targets)
SKIP_DOMAINS = {
    "google.com", "www.google.com",
    "github.com", "www.github.com",
    "stackoverflow.com", "www.stackoverflow.com",
    "amazon.com", "www.amazon.com",
    "microsoft.com", "www.microsoft.com",
    "facebook.com", "www.facebook.com",
    "twitter.com", "www.twitter.com",
    "linkedin.com", "www.linkedin.com",
    "apple.com", "www.apple.com",
    "netflix.com", "www.netflix.com",
}

def _should_skip_domain(target: str) -> bool:
    """Check if domain should be skipped due to known hardening."""
    domain = _as_domain(target).lower()
    base = _base_domain(domain)
    return base in SKIP_DOMAINS or domain in SKIP_DOMAINS

def _as_domain(target: str) -> str:
    """Normalize input to bare hostname/domain for DNS-style scanners."""
    value = (target or "").strip()
    if not value:
        return ""
    if "://" not in value:
        return value.split("/")[0].strip().lower()
    parsed = urlparse(value)
    return (parsed.hostname or "").strip().lower()

def _as_url(target: str) -> str:
    """Normalize input to URL for HTTP-style scanners."""
    value = (target or "").strip()
    if not value:
        return ""
    if "://" not in value:
        value = f"https://{value}"
    return value

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
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate.resolve())
    return None

def _check_nuclei_version(nuclei_path: str) -> tuple[bool, str]:
    """Check if nuclei version is 4.2.x or compatible."""
    try:
        result = subprocess.run([nuclei_path, "-version"], capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            return False, f"Failed to get version: {result.stderr}"
        
        version_output = result.stdout.strip()
        # Look for version pattern like "4.2.x" or "[4.2.x]"
        version_match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_output)
        if not version_match:
            return False, f"Could not parse version from: {version_output}"
        
        major, minor, patch = map(int, version_match.groups())
        if major == 4 and minor >= 2:
            return True, f"v{major}.{minor}.{patch}"
        else:
            return False, f"Version {major}.{minor}.{patch} is not compatible (need 4.2+)"
    except Exception as e:
        return False, f"Error checking version: {e}"

def _validate_nuclei_target(target: str) -> tuple[bool, str, list]:
    """Validate target and return normalized targets list."""
    if not target or not isinstance(target, str):
        return False, "Target must be a non-empty string", []
    
    target = target.strip()
    
    # Check if it's a JSON list of subdomains
    if target.startswith('[') and target.endswith(']'):
        try:
            subdomains = json.loads(target)
            if not isinstance(subdomains, list):
                return False, "Target list must be a JSON array", []
            
            # Validate list size to prevent DoS
            if len(subdomains) > MAX_SUBDOMAIN_LIST_SIZE:
                return False, f"Subdomain list exceeds maximum size of {MAX_SUBDOMAIN_LIST_SIZE}", []
            
            if len(subdomains) == 0:
                return False, "Subdomain list is empty", []
            
            # Validate each subdomain
            normalized = []
            for sub in subdomains:
                if not isinstance(sub, str):
                    return False, f"Invalid subdomain in list: {sub}", []
                domain = _as_domain(sub)
                if not domain:
                    return False, f"Invalid domain format: {sub}", []
                normalized.append(domain)
            
            return True, f"Validated {len(normalized)} subdomains", normalized
        except json.JSONDecodeError:
            return False, "Invalid JSON format for subdomain list", []
        except Exception as e:
            logger.exception(f"Error validating subdomain list: {e}")
            return False, "Error parsing subdomain list", []
    
    # Single target
    domain = _as_domain(target)
    if not domain:
        return False, f"Invalid domain format: {target}", []
    
    # Basic domain validation
    if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$', domain):
        return False, f"Domain contains invalid characters: {domain}", []
    
    return True, f"Validated single domain: {domain}", [domain]

def _get_fingerprint(cname: str):
    cname = (cname or "").lower().rstrip(".")
    for fp in TAKEOVER_FINGERPRINTS:
        if any(pattern in cname for pattern in fp["patterns"]):
            return fp
    return None

def _parse_burp_issue(issue: dict) -> dict | None:
    """Parse a single Burp Suite issue from JSON export into Finding dict."""
    try:
        # Extract key fields from Burp issue
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
        
        # Map Burp severity to internal
        severity_map = {
            "high": "high",
            "medium": "medium", 
            "low": "low",
            "information": "info",
            "info": "info"
        }
        internal_severity = severity_map.get(severity, "info")
        
        # Only import critical/high as per requirements
        if internal_severity not in ["critical", "high"]:
            logger.debug(f"Skipping Burp issue with severity {internal_severity}: {issue_name}")
            return None
        
        # Build asset (prefer URL, fallback to host)
        asset = url or f"https://{host}{path}"
        
        # Build finding title
        finding_title = issue_name or "Burp Suite Finding"
        
        # Build details
        details = f"Severity: {severity}; Confidence: {confidence}\n\n{issue_detail}"
        if issue_background:
            details += f"\n\nBackground: {issue_background}"
        if remediation:
            details += f"\n\nRemediation: {remediation}"
        
        # Build evidence with request/response
        evidence = {
            "request": request,
            "response": response,
            "burp_issue": issue  # Keep full issue for reference
        }
        
        # Build vulnerable objects
        vulnerable_objects = [{"url": asset, "type": "endpoint", "description": finding_title}]
        
        # Build H1 report
        h1_report = f"## {finding_title}\n\n**Summary:**\n{issue_detail}\n\n"
        
        # Add CVE if available
        cve = issue.get("cve")
        if cve:
            h1_report += f"**CVE:** {cve}\n\n"
        
        h1_report += f"**Steps to Reproduce:**\n1. Send the following request:\n```\n{request}\n```\n\n**Expected Response:**\n```\n{response}\n```\n\n**Impact:**\n{issue_background}\n\n**Remediation:**\n{remediation}"
        
        result = {
            "asset": asset,
            "finding": finding_title,
            "severity": internal_severity,
            "status": "new",
            "module": "burp-import",
            "details": details,
            "evidence": json.dumps(evidence),
            "vulnerable_objects": json.dumps(vulnerable_objects),
            "h1_report": h1_report
        }
        
        # Validate against HackerOne requirements
        if not validate_hackerone_finding(result):
            logger.debug(f"Burp issue failed HackerOne validation: {finding_title}")
            return None
            
        return result
    except Exception as e:
        logger.exception(f"Failed to parse Burp issue: {e}")
        return None

def _probe_subdomain_http(subdomain: str):
    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{subdomain}",
                timeout=8,
                verify=True,
                allow_redirects=True,
                headers=HEADERS,
            )
            return {"code": r.status_code, "body": r.text[:4000], "scheme": scheme}
        except requests.exceptions.ConnectionError:
            return {"code": 0, "body": "", "scheme": scheme}
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

def _enumerate_subdomains(domain: str):
    collected = set()
    logs = []
    tool_commands = []
    subfinder_path = _resolve_tool_path("subfinder")
    assetfinder_path = _resolve_tool_path("assetfinder")
    amass_path = _resolve_tool_path("amass")

    if subfinder_path:
        tool_commands.append(("subfinder", [subfinder_path, "-d", domain, "-silent"]))
    else:
        logs.append("[WARN] subfinder not found in PATH/common locations")

    if assetfinder_path:
        tool_commands.append(("assetfinder", [assetfinder_path, "--subs-only", domain]))
    else:
        logs.append("[WARN] assetfinder not found in PATH/common locations")

    if amass_path:
        tool_commands.append(("amass", [amass_path, "enum", "-passive", "-d", domain]))
    else:
        logs.append("[WARN] amass not found in PATH/common locations")

    for label, command in tool_commands:
        logs.append(f"Running {label} ({command[0]})...")
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=120)
            lines = [line.strip().lower() for line in result.stdout.splitlines() if line.strip()]
            for line in lines:
                if line.endswith(domain):
                    collected.add(line)
            logs.append(f"{label}: {len(lines)} results")
        except Exception as e:
            logs.append(f"[WARN] {label} failed: {e}")

    if not collected:
        logs.append("[WARN] No passive tool results, using DNS brute-force wordlist")
        logs.append("Trying crt.sh passive certificate enumeration...")
        try:
            crt = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=15)
            if crt.ok:
                entries = crt.json()
                crt_found = set()
                for entry in entries[:5000]:
                    names = str(entry.get("name_value", "")).splitlines()
                    for name in names:
                        candidate = name.strip().lower().lstrip("*.").rstrip(".")
                        if candidate.endswith(domain):
                            crt_found.add(candidate)
                for sub in crt_found:
                    collected.add(sub)
                logs.append(f"crt.sh: {len(crt_found)} candidate subdomains")
        except Exception as e:
            logs.append(f"[WARN] crt.sh lookup failed: {e}")

    for sub in _dns_brute(domain):
        collected.add(sub)
    return sorted(collected), logs


# ── Helper Functions (must be defined before scanners) ────────────────────────

def log(msg: str) -> dict:
    """Create a log event."""
    return {"type": "log", "message": msg, "timestamp": datetime.utcnow().isoformat()}

def finding(asset, detail, severity, description, h1_report) -> dict:
    """Create a finding event."""
    return {
        "type": "finding",
        "data": {
            "asset": asset,
            "finding": description,
            "severity": severity,
            "evidence": {"detail": detail},
            "h1_report": h1_report,
        }
    }

def _detect_provider(cname: str) -> str:
    """Detect hosting provider from CNAME."""
    fp = _get_fingerprint(cname)
    if fp:
        return fp["provider"]
    return "unknown"

def _takeover_severity(subdomain: str) -> str:
    """Determine takeover severity based on subdomain keywords."""
    sub = subdomain.lower()
    if any(k in sub for k in ["auth", "login", "sso", "oauth", "account", "identity"]):
        return "critical"
    if any(k in sub for k in ["api", "staging", "dev", "beta", "admin", "portal"]):
        return "high"
    return "medium"

def _base_domain(host: str) -> str:
    """Extract base domain from hostname."""
    parts = [p for p in (host or "").split(".") if p]
    if len(parts) <= 2:
        return host
    return ".".join(parts[-2:])

def _is_external_location(location: str, target_url: str, base_domain: str) -> bool:
    """Check if redirect location is external."""
    if not location:
        return False
    normalized = urljoin(target_url, location)
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if host == base_domain or host.endswith(f".{base_domain}"):
        return False
    return True

def _dns_brute(target: str):
    """Brute-force common DNS subdomains."""
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
    ]
    results = []
    for word in wordlist:
        sub = f"{word}.{target}"
        try:
            socket.getaddrinfo(sub, None)
            results.append(sub)
        except Exception:
            pass
    return results


# ── Subdomain Takeover ────────────────────────────────────────────────────────

def scan_subdomain_takeover(target: str, options: dict):
    domain = _as_domain(target)
    if not domain:
        yield log("[ERROR] Invalid target for subdomain takeover scan")
        return
    yield log(f"Starting subdomain takeover scan on {domain}")

    subdomains, enum_logs = _enumerate_subdomains(domain)
    for message in enum_logs:
        yield log(message)
    if not subdomains:
        subdomains = _dns_brute(domain)

    yield log(f"Found {len(subdomains)} subdomains")
    if not subdomains:
        yield log("No subdomains discovered; takeover scan cannot continue")
        yield log("Subdomain takeover scan complete.")
        return

    # DNS triage: keep only CNAME-backed subdomains for takeover analysis.
    cname_records = []
    for sub in subdomains:
        cname_target = _resolve_cname(sub)
        if cname_target:
            fp = _get_fingerprint(cname_target)
            cname_records.append(
                {
                    "sub": sub,
                    "cname": cname_target,
                    "provider": fp["provider"] if fp else "Unknown",
                    "fp": fp,
                }
            )

    yield log(f"CNAME triage complete: {len(cname_records)} CNAME candidates out of {len(subdomains)} subdomains")
    if not cname_records:
        yield log("No CNAME candidates found; no takeover vectors identified")
        yield log("Subdomain takeover scan complete.")
        return

    for record in cname_records:
        sub = record["sub"]
        cname_target = record["cname"]
        fp = record["fp"]
        provider = fp["provider"] if fp else _detect_provider(cname_target)
        yield log(f"Checking {sub} -> {cname_target} ({provider})")

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
            vulnerable = True
            confidence = "high"
        elif nxdomain and body_match:
            vulnerable = True
            confidence = "high"
        elif body_match and fp and fp.get("takeover"):
            vulnerable = True
            confidence = "medium"
        elif nxdomain and fp and fp.get("takeover"):
            vulnerable = True
            confidence = "medium"

        if vulnerable:
            severity = _takeover_severity(sub)
            detail = f"CNAME={cname_target}; HTTP={probe['code']}; NXDOMAIN={str(nxdomain).lower()}; confidence={confidence}"
            if match_string:
                detail += f"; fingerprint={match_string}"
            yield finding(
                sub,
                detail,
                severity,
                f"Subdomain takeover candidate on {sub} via {provider} ({confidence} confidence)",
                _takeover_report(sub, cname_target, provider),
            )

    yield log("Subdomain takeover scan complete.")


def takeover_enumerate(target: str):
    domain = _as_domain(target)
    if not domain:
        return {"target": target, "subdomains": [], "logs": ["[ERROR] Invalid target"]}
    subdomains, logs = _enumerate_subdomains(domain)
    return {"target": domain, "subdomains": subdomains, "logs": logs}


def takeover_triage(subdomains: list[str]):
    results = {"cname": [], "a": [], "dead": []}
    for sub in subdomains:
        cname = _resolve_cname(sub)
        if cname:
            fp = _get_fingerprint(cname)
            results["cname"].append({
                "sub": sub,
                "cname": cname,
                "provider": fp["provider"] if fp else "Unknown",
                "fp": fp,
            })
            continue
        try:
            ans = TAKEOVER_RESOLVER.resolve(sub, "A")
            ips = [str(r) for r in ans]
            results["a"].append({"sub": sub, "ips": ips})
        except Exception:
            results["dead"].append({"sub": sub})
    return results


def takeover_scan_cnames(cname_records):
    vulnerabilities = []
    logs = []
    
    # Handle both list of dicts and list of strings
    records = []
    for record in cname_records:
        if isinstance(record, dict):
            records.append(record)
        elif isinstance(record, str):
            # If it's a string, treat it as a subdomain and look up its CNAME
            sub = record.strip()
            if sub:
                cname_target = _resolve_cname(sub)
                if cname_target:
                    fp = _get_fingerprint(cname_target)
                    records.append({
                        "sub": sub,
                        "cname": cname_target,
                        "fp": fp,
                        "provider": fp["provider"] if fp else _detect_provider(cname_target)
                    })
                else:
                    logs.append(f"No CNAME found for {sub}")
    
    for record in records:
        sub = record.get("sub", "")
        cname_target = record.get("cname", "")
        fp = record.get("fp")
        provider = record.get("provider") or (fp["provider"] if fp else _detect_provider(cname_target))
        logs.append(f"Scanning {sub} -> {cname_target} ({provider})")

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
            vulnerable = True
            confidence = "high"
        elif nxdomain and body_match:
            vulnerable = True
            confidence = "high"
        elif body_match and fp and fp.get("takeover"):
            vulnerable = True
            confidence = "medium"
        elif nxdomain and fp and fp.get("takeover"):
            vulnerable = True
            confidence = "medium"

        if vulnerable:
            vulnerabilities.append({
                "sub": sub,
                "cname": cname_target,
                "provider": provider,
                "nxdomain": nxdomain,
                "http_code": probe["code"],
                "body_match": body_match,
                "match_string": match_string,
                "confidence": confidence,
                "severity": _takeover_severity(sub),
            })
    return {"vulnerable": vulnerabilities, "logs": logs}


def takeover_verify(vulnerable_list: list[dict]):
    verified = []
    logs = []
    for item in vulnerable_list:
        sub = item.get("sub", "")
        cname = item.get("cname", "")
        logs.append(f"Verifying {sub}...")
        nxdomain_1 = _check_nxdomain(cname)
        nxdomain_2 = _check_nxdomain(cname)
        probe = _probe_subdomain_http(sub)
        cname_check = _resolve_cname(sub)
        is_confirmed = bool(cname_check) and (cname_check == cname or cname in cname_check) and (nxdomain_1 or nxdomain_2) and probe["code"] in (0, 404, -1)
        verified.append({
            **item,
            "verify_nxdomain_1": nxdomain_1,
            "verify_nxdomain_2": nxdomain_2,
            "verify_http": probe["code"],
            "cname_still_present": bool(cname_check),
            "verified": is_confirmed,
        })
    return {"verified": verified, "logs": logs}


# ── S3 / Blob Bucket ──────────────────────────────────────────────────────────

def scan_s3_buckets(target: str, options: dict):
    yield log(f"Scanning S3/Blob buckets for {target}")
    domain = _as_domain(target)
    if not domain:
        yield log("[ERROR] Invalid target for bucket scan")
        return
    name = domain.split(".")[0]

    candidates = [
        f"{name}", f"{name}-backup", f"{name}-dev", f"{name}-staging",
        f"{name}-prod", f"{name}-assets", f"{name}-static", f"{name}-media",
        f"{name}-uploads", f"{name}-data", f"www-{name}", f"api-{name}",
    ]

    for bucket in candidates:
        # AWS S3
        url = f"https://{bucket}.s3.amazonaws.com"
        yield log(f"Checking {url}")
        try:
            r = requests.get(url, headers=HEADERS, timeout=8)
            if r.status_code == 200 and "<ListBucketResult" in r.text:
                yield finding(url, bucket, "critical",
                              "Public S3 bucket — directory listing exposed",
                              _bucket_report(url, "AWS S3", "public listing"))
            elif r.status_code == 403:
                # 403 alone means the bucket is present but access-controlled.
                # Treat as informational to avoid false positives.
                yield log(f"{bucket} — exists but access denied (403), not flagged as vulnerability")
            elif "NoSuchBucket" in r.text:
                yield log(f"{bucket} — NoSuchBucket")
        except Exception as e:
            yield log(f"[ERR] {bucket}: {e}")

        # Azure Blob
        az_url = f"https://{bucket}.blob.core.windows.net"
        try:
            r = requests.get(az_url, headers=HEADERS, timeout=8)
            if r.status_code in [200, 400] and "BlobServiceProperties" not in r.text:
                yield finding(az_url, bucket, "high",
                              "Azure Blob container potentially exposed",
                              _bucket_report(az_url, "Azure Blob", str(r.status_code)))
        except Exception:
            pass

    yield log("Bucket scan complete.")


# ── CORS ──────────────────────────────────────────────────────────────────────

def scan_cors(target: str, options: dict):
    target_url = _as_url(target)
    target_host = _as_domain(target)
    if not target_url or not target_host:
        yield log("[ERROR] Invalid target for CORS scan")
        return
    yield log(f"Scanning CORS on {target_url}")
    evil_origins = [
        "https://evil.com",
        f"https://evil.{target_host}",
        f"https://{target_host}.evil.com",
        "null",
    ]
    for origin in evil_origins:
        yield log(f"Testing Origin: {origin}")
        try:
            r = requests.get(target_url, headers={**HEADERS, "Origin": origin}, timeout=8)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == origin or acao == "*":
                sev = "high" if acac.lower() == "true" else "medium"
                yield finding(target_url, origin, sev,
                              f"CORS reflects arbitrary origin: {acao}, Credentials: {acac}",
                              _cors_report(target_url, origin, acao, acac))
        except Exception as e:
            yield log(f"[ERR] {e}")
    yield log("CORS scan complete.")


# ── Sensitive Files ───────────────────────────────────────────────────────────

def scan_sensitive_files(target: str, options: dict):
    base = _as_url(target).rstrip("/")
    if not base:
        yield log("[ERROR] Invalid target for sensitive files scan")
        return
    yield log(f"Scanning sensitive file exposure on {base}")

    # Get configurable parameters
    max_workers = options.get("max_workers", min(20, (os.cpu_count() or 1) + 4))
    request_timeout = options.get("timeout", 8)
    # Validate timeout is within reasonable bounds
    request_timeout = max(MIN_REQUEST_TIMEOUT, min(request_timeout, MAX_REQUEST_TIMEOUT))

    def check(path):
        url = base + path
        try:
            r = requests.get(url, headers=HEADERS, timeout=request_timeout, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                return url, r.status_code, len(r.content)
        except requests.exceptions.Timeout:
            return None
        except Exception as e:
            logger.debug(f"Error checking {url}: {e}")
            pass
        return None

    try:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = {ex.submit(check, p): p for p in SENSITIVE_PATHS}
            for fut in futures:
                try:
                    result = fut.result(timeout=request_timeout + 5)
                    if result:
                        url, code, size = result
                        yield log(f"⚠️  EXPOSED: {url} ({code}, {size}b)")
                yield finding(url, futures[fut], "high",
                              f"Sensitive file exposed: HTTP {code}, {size} bytes",
                              _sensitive_report(url))

    yield log("Sensitive file scan complete.")


# ── API Key Leak (JS scanning) ────────────────────────────────────────────────

def scan_api_key_leak(target: str, options: dict):
    target_url = _as_url(target)
    if not target_url:
        yield log("[ERROR] Invalid target for API key leak scan")
        return
    yield log(f"Scanning for API key leaks in JS on {target_url}")
    patterns = {
        "AWS Key": r"AKIA[0-9A-Z]{16}",
        "Google API": r"AIza[0-9A-Za-z\-_]{35}",
        "Stripe Secret": r"sk_live_[0-9a-zA-Z]{24}",
        "Stripe Public": r"pk_live_[0-9a-zA-Z]{24}",
        "GitHub Token": r"ghp_[0-9a-zA-Z]{36}",
        "Slack Token": r"xox[baprs]-[0-9a-zA-Z\-]{10,48}",
        "Private Key": r"-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----",
        "Bearer Token": r"Bearer [a-zA-Z0-9\-._~+/]{20,}",
        "JWT": r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+",
    }

    try:
        r = requests.get(target_url, headers=HEADERS, timeout=10)
        js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', r.text)
        js_urls = [urljoin(target_url, u) for u in js_urls]
    except Exception as e:
        yield log(f"[ERR] Fetching target: {e}")
        return

    yield log(f"Found {len(js_urls)} JS files to scan")

    for js_url in js_urls[:50]:  # cap at 50
        yield log(f"Scanning {js_url}")
        try:
            r = requests.get(js_url, headers=HEADERS, timeout=10)
            for key_type, pattern in patterns.items():
                matches = re.findall(pattern, r.text)
                for match in matches:
                    yield finding(js_url, match[:40] + "...", "critical",
                                  f"{key_type} found in JS file",
                                  _apikey_report(js_url, key_type, match))
        except Exception as e:
            yield log(f"[ERR] {js_url}: {e}")

    yield log("API key leak scan complete.")


# ── Open Redirect ─────────────────────────────────────────────────────────────

def scan_open_redirect(target: str, options: dict):
    target_url = _as_url(target)
    if not target_url:
        yield log("[ERROR] Invalid target for open redirect scan")
        return
    
    # Skip known hardened/safe domains
    if _should_skip_domain(target):
        yield log(f"[SKIP] Skipping {target} — known hardened domain")
        return
    
    yield log(f"Scanning open redirects on {target_url}")
    target_host = (urlparse(target_url).hostname or "").lower()
    base_domain = _base_domain(target_host)
    payload = "https://evil.com"

    for param in REDIRECT_PARAMS:
        separator = "&" if "?" in target_url else "?"
        url = f"{target_url}{separator}{param}={payload}"
        yield log(f"Testing {url}")
        try:
            r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=False)
            loc = r.headers.get("Location", "")
            # Only flag if: (1) status is redirect AND (2) Location is truly external
            # Avoid false positives: if redirect goes to target's own domain with parameter appended, it's safe
            if r.status_code in (301, 302, 303, 307, 308) and _is_external_location(loc, target_url, base_domain):
                yield finding(url, param, "medium",
                              f"Open redirect via parameter '{param}' → {loc}",
                              _redirect_report(url, param, loc))
        except Exception as e:
            yield log(f"[ERR] {e}")

    yield log("Open redirect scan complete.")


# ── Clickjacking ──────────────────────────────────────────────────────────────

def scan_clickjacking(target: str, options: dict):
    target_url = _as_url(target)
    if not target_url:
        yield log("[ERROR] Invalid target for clickjacking scan")
        return
    yield log(f"Scanning clickjacking on {target_url}")
    try:
        r = requests.get(target_url, headers=HEADERS, timeout=10)
        xfo = r.headers.get("X-Frame-Options", "")
        csp = r.headers.get("Content-Security-Policy", "")

        if not xfo and "frame-ancestors" not in csp.lower():
            yield finding(target_url, "missing headers", "medium",
                          "No X-Frame-Options or CSP frame-ancestors — clickjacking possible",
                          _clickjack_report(target_url))
        else:
            yield log(f"Protected: X-Frame-Options={xfo}, CSP frame-ancestors present={bool('frame-ancestors' in csp.lower())}")
    except Exception as e:
        yield log(f"[ERR] {e}")

    yield log("Clickjacking scan complete.")


# ── DNS Zone Transfer ─────────────────────────────────────────────────────────

def scan_dns_zone_transfer(target: str, options: dict):
    domain = _as_domain(target)
    if not domain:
        yield log("[ERROR] Invalid target for zone transfer scan")
        return
    yield log(f"Attempting DNS zone transfer on {domain}")
    try:
        ns_answers = dns.resolver.resolve(domain, "NS")
        for ns in ns_answers:
            ns_str = str(ns).rstrip(".")
            yield log(f"Trying AXFR on {ns_str}")
            try:
                zone = dns.query.xfr(ns_str, domain, timeout=10)
                z = dns.zone.from_xfr(zone)
                records = [str(n) for n in z.nodes.keys()]
                yield finding(domain, ns_str, "high",
                              f"Zone transfer succeeded — {len(records)} records exposed",
                              _zone_transfer_report(domain, ns_str, records))
            except Exception as e:
                yield log(f"{ns_str} — refused: {e}")
    except Exception as e:
        yield log(f"[ERR] {e}")

    yield log("Zone transfer scan complete.")


# ── SPF / DMARC ───────────────────────────────────────────────────────────────

def scan_spf_dmarc(target: str, options: dict):
    domain = _as_domain(target)
    if not domain:
        yield log("[ERROR] Invalid target for SPF/DMARC scan")
        return
    yield log(f"Checking SPF/DMARC for {domain}")

    # SPF
    try:
        txt = dns.resolver.resolve(domain, "TXT")
        spf_records = [r.to_text() for r in txt if "v=spf1" in r.to_text().lower()]
        if not spf_records:
            yield finding(domain, "SPF", "medium",
                          "No SPF record found — email spoofing possible",
                          _email_spoof_report(domain, "SPF"))
        else:
            yield log(f"SPF: {spf_records[0]}")
            if "+all" in spf_records[0]:
                yield finding(domain, "SPF", "high",
                              "SPF uses +all — accepts all senders",
                              _email_spoof_report(domain, "SPF +all"))
    except Exception as e:
        yield log(f"[ERR] SPF: {e}")

    # DMARC
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        records = [r.to_text() for r in dmarc]
        yield log(f"DMARC: {records[0] if records else 'none'}")
        if not records:
            yield finding(domain, "DMARC", "medium",
                          "No DMARC record — email spoofing not mitigated",
                          _email_spoof_report(domain, "DMARC"))
        elif "p=none" in records[0].lower():
            yield finding(domain, "DMARC", "low",
                          "DMARC policy is p=none — monitoring only, no enforcement",
                          _email_spoof_report(domain, "DMARC p=none"))
    except Exception as e:
        yield log(f"[ERR] DMARC: {e}")

    yield log("SPF/DMARC scan complete.")


# ── Rate Limit ────────────────────────────────────────────────────────────────

def scan_rate_limit(target: str, options: dict):
    target_url = _as_url(target)
    if not target_url:
        yield log("[ERROR] Invalid target for rate limit scan")
        return
    
    # Skip known hardened/safe domains
    if _should_skip_domain(target):
        yield log(f"[SKIP] Skipping {target} — known hardened domain with built-in protections")
        return
    
    yield log(f"Testing rate limiting on {target_url}")
    count = options.get("requests", 30)

    codes = []
    for i in range(count):
        try:
            r = requests.post(target_url, json={"test": i}, headers=HEADERS, timeout=5)
            codes.append(r.status_code)
            yield log(f"Request {i+1}: {r.status_code}")
        except Exception as e:
            yield log(f"[ERR] {e}")

    if not codes:
        yield log("Rate limit test inconclusive — no successful HTTP responses received")
    elif all(code in {401, 403, 404, 405} for code in codes):  # Fixed duplicate 405
        yield log(f"Rate limit test inconclusive — endpoint blocked/unauthorized ({set(codes)})")
    elif 429 not in codes:
        yield finding(target_url, "rate-limit", "medium",
                      f"No rate limiting detected after {count} requests — all returned {set(codes)}",
                      _ratelimit_report(target_url, count))
    else:
        yield log(f"Rate limiting active — 429 received after {codes.index(429)+1} requests")

    yield log("Rate limit scan complete.")


# ── Nuclei Scanner ────────────────────────────────────────────────────────────

def scan_nuclei(target: str, options: dict):
    """Run Nuclei scan on target and parse results."""
    yield log("[NUCLEI] Starting nuclei vulnerability scan pipeline")
    
    # Step 1: Validate target input
    yield log(f"[NUCLEI] Validating target input: {target[:100]}{'...' if len(target) > 100 else ''}")
    is_valid, validation_msg, target_list = _validate_nuclei_target(target)
    if not is_valid:
        yield log(f"[NUCLEI ERROR] Target validation failed: {validation_msg}")
        return
    
    yield log(f"[NUCLEI] {validation_msg}")
    
    # Step 2: Resolve nuclei binary
    yield log("[NUCLEI] Resolving nuclei binary path")
    nuclei_path = _resolve_tool_path("nuclei")
    if not nuclei_path:
        # Try current directory
        local_nuclei = Path.cwd() / "nuclei.exe"
        if local_nuclei.exists():
            nuclei_path = str(local_nuclei)
        else:
            yield log("[NUCLEI ERROR] Nuclei binary not found in PATH or common locations")
            yield log("[NUCLEI ERROR] Please install nuclei v3.3+ from https://github.com/projectdiscovery/nuclei")
            return
    
    yield log(f"[NUCLEI] Found nuclei at: {nuclei_path}")
    
    # Step 3: Check nuclei version
    yield log("[NUCLEI] Checking nuclei version compatibility")
    version_ok, version_msg = _check_nuclei_version(nuclei_path)
    if not version_ok:
        yield log(f"[NUCLEI ERROR] Version check failed: {version_msg}")
        return
    
    yield log(f"[NUCLEI] Version check passed: {version_msg}")
    
    # Step 4: Prepare scan targets
    scan_targets = []
    for domain in target_list:
        # Convert to URL format for nuclei
        url = f"https://{domain}"
        scan_targets.append(url)
    
    yield log(f"[NUCLEI] Prepared {len(scan_targets)} scan targets")
    
    total_findings = 0
    
    # Step 5: Run nuclei on each target
    for i, target_url in enumerate(scan_targets, 1):
        yield log(f"[NUCLEI] Scanning target {i}/{len(scan_targets)}: {target_url}")
        
        # Build nuclei command
        cmd = [
            nuclei_path,
            "-u", target_url,
            "-jsonl",  # Output in JSONL format
            "-silent",  # Reduce noise
            "-no-interactsh",  # Disable interactsh for speed
        ]
        
        # Add timeout from options (default 30 seconds)
        timeout_seconds = options.get("timeout", 30)
        cmd.extend(["-timeout", str(int(timeout_seconds))])
        
        # Add severity filter - only critical/high as per requirements
        cmd.extend(["-severity", "critical,high"])
        
        # Add templates path if specified
        templates = options.get("templates", "")
        if templates and isinstance(templates, str) and templates.strip():
            cmd.extend(["-t", templates.strip()])
        
        # Add rate limiting from options (default 10)
        rate_limit = options.get("rate-limit", 10)
        cmd.extend(["-rate-limit", str(int(rate_limit))])
        
        yield log(f"[NUCLEI] Executing command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True,
                timeout=options.get("process_timeout", 600)
            )
            
            yield log(f"[NUCLEI] Command completed with return code: {result.returncode}")
            
            # Check return code - nuclei returns 0 on success, non-zero on errors
            # Some warnings might return exit code 2, which should be logged but not fail the scan
            if result.returncode != 0:
                stderr_msg = result.stderr.strip()
                stdout_msg = result.stdout.strip()[:500]  # First 500 chars
                # Treat 2 as warning (template errors), others as hard failures
                if result.returncode == 2:
                    yield log(f"[NUCLEI WARN] Nuclei exited with code 2 (template or config warnings)")
                    if stderr_msg:
                        yield log(f"[NUCLEI WARN] STDERR: {stderr_msg[:200]}")
                else:
                    yield log(f"[NUCLEI ERROR] Nuclei process failed (code {result.returncode})")
                    yield log(f"[NUCLEI ERROR] STDERR: {stderr_msg[:200]}")
                    if stdout_msg:
                        yield log(f"[NUCLEI ERROR] STDOUT: {stdout_msg}")
                    continue
            
            # Parse JSON output
            stdout = result.stdout.strip()
            if not stdout:
                # Distinguish between "no vulnerabilities" (exit 0) vs crash
                if result.returncode == 0:
                    yield log(f"[NUCLEI] Completed: No vulnerabilities found on {target_url}")
                else:
                    yield log(f"[NUCLEI WARN] Nuclei produced no output for {target_url} (may have failed)")
                continue
            
            lines = stdout.split('\n')
            yield log(f"[NUCLEI] Processing {len(lines)} output lines from {target_url}")
            
            target_findings = 0
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line:
                    continue
                
                try:
                    finding_data = json.loads(line)
                except json.JSONDecodeError as e:
                    # Log full error, not truncated
                    yield log(f"[NUCLEI ERROR] Invalid JSON on line {line_num}: {str(e)}")
                    yield log(f"[NUCLEI ERROR] Line preview: {line[:300]}")
                    continue
                except Exception as e:
                    yield log(f"[NUCLEI ERROR] Unexpected error on line {line_num}: {str(e)}")
                    continue
                
                try:
                    parsed = _parse_nuclei_finding(finding_data, target_url)
                    if parsed:
                        yield finding(**parsed)
                        target_findings += 1
                        total_findings += 1
                    else:
                        template_id = finding_data.get('template-id', 'unknown')
                        yield log(f"[NUCLEI WARN] Finding filtered by validation: {template_id}")
                except Exception as e:
                    yield log(f"[NUCLEI ERROR] Error processing finding: {str(e)}")
            
            yield log(f"[NUCLEI] Completed scanning {target_url} - found {target_findings} valid findings")
            
        except subprocess.TimeoutExpired:
            yield log(f"[NUCLEI ERROR] Nuclei scan timed out after 10 minutes for {target_url}")
        except FileNotFoundError:
            yield log(f"[NUCLEI ERROR] Nuclei binary not found at {nuclei_path}")
        except PermissionError:
            yield log(f"[NUCLEI ERROR] Permission denied executing nuclei at {nuclei_path}")
        except OSError as e:
            yield log(f"[NUCLEI ERROR] OS error executing nuclei: {e}")
        except Exception as e:
            yield log(f"[NUCLEI ERROR] Unexpected error during nuclei execution: {type(e).__name__}: {e}")
    
    yield log(f"[NUCLEI] Scan pipeline complete. Total findings across all targets: {total_findings}")
    yield log("[NUCLEI] Nuclei vulnerability scan finished")


def _validate_url(url: str) -> bool:
    """Validate that URL is properly formatted and safe."""
    try:
        if not url or not isinstance(url, str):
            return False
        parsed = urlparse(url)
        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            return False
        # Scheme must be http/https
        if parsed.scheme not in ['http', 'https']:
            return False
        return True
    except Exception:
        return False


def _parse_nuclei_finding(data: dict, fallback_url: str = "") -> dict | None:
    """Parse Nuclei JSON finding into internal format."""
    try:
        # Validate required fields
        if not isinstance(data, dict):
            return None
        
        template_id = str(data.get("template-id", "")).strip()
        if not template_id or not isinstance(template_id, str):
            return None
        
        info = data.get("info", {})
        if not isinstance(info, dict):
            return None
        
        severity = str(data.get("severity", "info")).lower().strip()
        url = str(data.get("url", "")).strip()
        matched_at = str(data.get("matched-at", "")).strip()
        
        # Use fallback URL if provided and primary URL is invalid
        asset = matched_at or url or fallback_url
        if not asset or not _validate_url(asset):
            return None
        
        # Map severity
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info"
        }
        internal_severity = severity_map.get(severity, "info")
        
        # Only critical/high
        if internal_severity not in ["critical", "high"]:
            return None
        
        # Asset was validated above
        
        # Build title - validate name is a string
        name = str(info.get("name", template_id)).strip()
        if not name:
            name = template_id
        finding_title = f"Nuclei: {name}"
        
        # Build details with proper validation
        details = f"Template: {template_id}\nSeverity: {severity}\n"
        description = str(info.get("description", "")).strip()
        if description:
            details += f"Description: {description}\n"
        
        tags = info.get("tags", [])
        if tags and isinstance(tags, list):
            # Ensure all tags are strings
            tag_strs = [str(t).strip() for t in tags if str(t).strip()]
            if tag_strs:
                details += f"Tags: {', '.join(tag_strs)}\n"
        
        extracted_results = data.get("extracted-results", [])
        if extracted_results and isinstance(extracted_results, list):
            # Validate and sanitize extracted results
            valid_results = [str(r).strip() for r in extracted_results if str(r).strip()]
            if valid_results:
                # Use JSON encoding to safely handle special characters
                details += f"Extracted: {json.dumps(valid_results)}\n"
        
        # Build evidence
        curl_command = data.get("curl-command", "")
        evidence = {
            "nuclei_data": data,
            "curl_command": curl_command
        }
        
        # Build vulnerable objects
        vulnerable_objects = [{"url": asset, "type": "endpoint", "description": finding_title}]
        
        # Build H1 report
        h1_report = f"## {finding_title}\n\n**Summary:**\n{info.get('description', 'Nuclei detected vulnerability')}\n\n"
        
        # Add CVE if available and valid format (CVE-YYYY-XXXXX)
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
        
        if extracted_results and isinstance(extracted_results, list):
            extracted_strs = [str(r).strip() for r in extracted_results if str(r).strip()]
            if extracted_strs:
                h1_report += f"**Extracted Data:**\n```\n{chr(10).join(extracted_strs)}\n```\n\n"
        
        impact = str(info.get("impact", "")).strip()
        remediation = str(info.get("remediation", "")).strip()
        h1_report += f"**Impact:**\n{impact or 'See description'}\n\n**Remediation:**\n{remediation or 'Fix the underlying issue'}"
        
        result = {
            "asset": asset,
            "finding": finding_title,
            "severity": internal_severity,
            "status": "new",
            "module": "nuclei",
            "details": details,
            "evidence": json.dumps(evidence),
            "vulnerable_objects": json.dumps(vulnerable_objects),
            "h1_report": h1_report
        }
        
        # Validate against HackerOne requirements
        if not validate_hackerone_finding(result):
            # Validation failed - log this for debugging but don't print
            return None
            
        return result
    except Exception as e:
        # Silently return None on parsing errors - log would be at caller level
        return None

def validate_hackerone_finding(finding: dict) -> bool:
    """Validate finding against HackerOne submission requirements with comprehensive checks."""
    try:
        severity = finding.get("severity", "").lower()
        details = finding.get("details", "")
        evidence = finding.get("evidence", "{}")
        vulnerable_objects = finding.get("vulnerable_objects", "[]")
        finding_title = finding.get("finding", "")
        
        # 1. Only critical/high severity
        if severity not in ["critical", "high"]:
            return False
        
        # 2. Must have affected endpoint URL
        asset = finding.get("asset", "")
        if not asset or not _validate_url(asset):
            return False
        
        # 3. Must have vulnerability type and impact description
        if not finding_title or not details or len(details) < 20:
            return False
        
        # 4. Must have reproduction steps (concrete PoC)
        h1_report = finding.get("h1_report", "")
        if not h1_report or "Steps to Reproduce" not in h1_report or len(h1_report) < 50:
            return False
        
        # 5. Check for concrete PoC (curl command, screenshot, or payload)
        evidence_data = json.loads(evidence) if isinstance(evidence, str) else evidence
        vulnerable_objs = json.loads(vulnerable_objects) if isinstance(vulnerable_objects, str) else vulnerable_objects
        
        has_concrete_poc = False
        
        # Check for curl command or HTTP request in evidence
        if evidence_data.get("curl_command") or evidence_data.get("request") or "curl" in h1_report.lower():
            has_concrete_poc = True
        
        # Check for extracted results (payloads, data)
        if evidence_data.get("nuclei_data") or evidence_data.get("extracted_results"):
            has_concrete_poc = True
        
        # Check H1 report for concrete indicators
        if any(marker in h1_report.lower() for marker in ["```bash", "```", "payload", "curl", "request"]):
            has_concrete_poc = True
        
        # Check vulnerable objects - must have at least one valid URL
        if not vulnerable_objs:
            return False
        
        valid_vuln_obj = any(
            isinstance(obj, dict) and _validate_url(obj.get("url", ""))
            for obj in vulnerable_objs
        )
        if not valid_vuln_obj:
            return False
        
        return has_concrete_poc
        
    except Exception as e:
        return False


# ── Report Templates ──────────────────────────────────────────────────────────

def _takeover_report(sub, cname, provider):
    return f"""## Subdomain Takeover via Dangling {provider} CNAME on {sub}

**Summary:**
{sub} has a dangling CNAME record pointing to a deprovisioned {provider} resource ({cname}).

**Steps to Reproduce:**
1. dig {sub} CNAME +noall +answer
2. dig @8.8.8.8 {cname}  → NXDOMAIN
3. curl -sk -o /dev/null -w "%{{http_code}}" https://{sub}  → 000

**Impact:** Attacker can claim {cname} and serve malicious content under the target's domain.

**Header:** X-Bug-Bounty: HackerOne-stickybugger"""

def _bucket_report(url, provider, detail):
    return f"""## Exposed {provider} Bucket: {url}

**Finding:** {detail}
**Steps to Reproduce:**
1. curl -sk "{url}"
2. Observe response — bucket listing or existence confirmed

**Impact:** Data exposure, potential write access, brand abuse."""

def _cors_report(target, origin, acao, acac):
    return f"""## CORS Misconfiguration on {target}

**Reflected Origin:** {acao}
**Credentials Allowed:** {acac}
**Test Origin:** {origin}

**Steps to Reproduce:**
curl -H "Origin: {origin}" -I {target}

**Impact:** Cross-origin data theft {'with credentials' if acac else ''}."""

def _sensitive_report(url):
    return f"""## Sensitive File Exposed: {url}

**Steps to Reproduce:**
curl -sk {url}

**Impact:** Credential exposure, config leak, source code disclosure."""

def _apikey_report(js_url, key_type, match):
    return f"""## {key_type} Exposed in JavaScript

**File:** {js_url}
**Pattern Match:** {match[:40]}...

**Steps to Reproduce:**
1. curl -sk {js_url} | grep -E "AKIA|AIza|sk_live|ghp_"

**Impact:** Full account compromise depending on key permissions."""

def _redirect_report(url, param, location):
    return f"""## Open Redirect via {param} Parameter

**URL:** {url}
**Redirects to:** {location}

**Steps to Reproduce:**
curl -I "{url}"

**Impact:** Phishing, token theft via redirect."""

def _clickjack_report(target):
    return f"""## Clickjacking Vulnerability on {target}

**Missing Headers:** X-Frame-Options, CSP frame-ancestors

**PoC:**
<iframe src="{target}" width="800" height="600"></iframe>

**Impact:** UI redressing attacks, forced clicks."""

def _zone_transfer_report(target, ns, records):
    return f"""## DNS Zone Transfer on {target}

**Nameserver:** {ns}
**Records Exposed:** {len(records)}
**Sample:** {', '.join(records[:5])}

**Steps to Reproduce:**
dig AXFR {target} @{ns}

**Impact:** Full subdomain enumeration, internal infrastructure mapping."""

def _email_spoof_report(target, issue):
    return f"""## Email Spoofing via {issue} Misconfiguration on {target}

**Issue:** {issue} not properly configured

**Steps to Reproduce:**
dig TXT {target}
dig TXT _dmarc.{target}

**Impact:** Attacker can send emails appearing to be from @{target}."""

def _ratelimit_report(target, count):
    return f"""## Missing Rate Limiting on {target}

**Test:** {count} requests sent — no 429 received

**Steps to Reproduce:**
for i in $(seq 1 {count}); do curl -s -o /dev/null -w "%{{http_code}}\\n" -X POST {target}; done

**Impact:** Brute force on login/OTP/reset endpoints."""
