"""
scanners.py — All BBH scanner modules.
Each scanner is a generator that yields dicts:
  {"type": "log", "message": str}
  {"type": "finding", "data": {...}}
  {"type": "complete"}
"""

import subprocess, dns.resolver, dns.query, dns.zone, requests, re, json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

HEADERS = {"User-Agent": "Mozilla/5.0 (BBH-Scanner; HackerOne-stickybugger)"}
TAKEOVER_FINGERPRINTS = {
    "amazonaws.com": "NoSuchBucket|The specified bucket does not exist",
    "azurewebsites.net": "404 Web Site not found",
    "github.io": "There isn't a GitHub Pages site here",
    "fastly.net": "Fastly error: unknown domain",
    "herokudns.com": "No such app",
    "shopify.com": "Sorry, this shop is currently unavailable",
    "squarespace.com": "No Such Account",
    "wpengine.com": "The site you were looking for couldn't be found",
    "surge.sh": "project not found",
    "netlify.com": "Not Found",
    "ghost.io": "The thing you were looking for is no longer here",
}

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


# ── Subdomain Takeover ────────────────────────────────────────────────────────

def scan_subdomain_takeover(target: str, options: dict):
    yield log(f"Starting subdomain takeover scan on {target}")

    # Enumerate subdomains via subfinder
    yield log("Running subfinder...")
    try:
        result = subprocess.run(
            ["subfinder", "-d", target, "-silent"],
            capture_output=True, text=True, timeout=120
        )
        subdomains = [s.strip() for s in result.stdout.splitlines() if s.strip()]
    except FileNotFoundError:
        yield log("[WARN] subfinder not found — using DNS brute fallback")
        subdomains = _dns_brute(target)

    yield log(f"Found {len(subdomains)} subdomains")

    for sub in subdomains:
        yield log(f"Checking {sub}...")
        try:
            cname_answer = dns.resolver.resolve(sub, "CNAME")
            cname_target = str(cname_answer[0].target).rstrip(".")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.resolver.NoNameservers, Exception):
            continue

        # Check if CNAME target resolves
        try:
            dns.resolver.resolve(cname_target, "A")
            # Resolves — check fingerprint via HTTP
            try:
                r = requests.get(f"https://{sub}", headers=HEADERS, timeout=8, verify=False)
                body = r.text.lower()
                for provider, pattern in TAKEOVER_FINGERPRINTS.items():
                    if provider in cname_target and re.search(pattern.lower(), body):
                        yield finding(sub, cname_target, "high",
                                      f"Fingerprint match: {pattern}",
                                      _takeover_report(sub, cname_target, provider))
            except Exception:
                pass
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            # CNAME target doesn't resolve — dangling
            yield log(f"⚠️  DANGLING CNAME: {sub} → {cname_target}")
            provider = _detect_provider(cname_target)
            yield finding(sub, cname_target, "high",
                          f"Dangling CNAME → {cname_target} (NXDOMAIN)",
                          _takeover_report(sub, cname_target, provider))
        except Exception as e:
            yield log(f"[ERR] {sub}: {e}")

    yield log("Subdomain takeover scan complete.")


# ── S3 / Blob Bucket ──────────────────────────────────────────────────────────

def scan_s3_buckets(target: str, options: dict):
    yield log(f"Scanning S3/Blob buckets for {target}")
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
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
                yield finding(url, bucket, "medium",
                              "S3 bucket exists but access denied — verify write access",
                              _bucket_report(url, "AWS S3", "403 exists"))
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
    yield log(f"Scanning CORS on {target}")
    evil_origins = [
        "https://evil.com",
        f"https://evil.{target}",
        f"https://{target}.evil.com",
        "null",
    ]
    for origin in evil_origins:
        yield log(f"Testing Origin: {origin}")
        try:
            r = requests.get(target, headers={**HEADERS, "Origin": origin}, timeout=8)
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao == origin or acao == "*":
                sev = "high" if acac.lower() == "true" else "medium"
                yield finding(target, origin, sev,
                              f"CORS reflects arbitrary origin: {acao}, Credentials: {acac}",
                              _cors_report(target, origin, acao, acac))
        except Exception as e:
            yield log(f"[ERR] {e}")
    yield log("CORS scan complete.")


# ── Sensitive Files ───────────────────────────────────────────────────────────

def scan_sensitive_files(target: str, options: dict):
    yield log(f"Scanning sensitive file exposure on {target}")
    base = target.rstrip("/")

    def check(path):
        url = base + path
        try:
            r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=False)
            if r.status_code == 200 and len(r.content) > 0:
                return url, r.status_code, len(r.content)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check, p): p for p in SENSITIVE_PATHS}
        for fut in futures:
            result = fut.result()
            if result:
                url, code, size = result
                yield log(f"⚠️  EXPOSED: {url} ({code}, {size}b)")
                yield finding(url, futures[fut], "high",
                              f"Sensitive file exposed: HTTP {code}, {size} bytes",
                              _sensitive_report(url))

    yield log("Sensitive file scan complete.")


# ── API Key Leak (JS scanning) ────────────────────────────────────────────────

def scan_api_key_leak(target: str, options: dict):
    yield log(f"Scanning for API key leaks in JS on {target}")
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
        r = requests.get(target, headers=HEADERS, timeout=10)
        js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', r.text)
        base = target.rstrip("/")
        js_urls = [u if u.startswith("http") else base + u for u in js_urls]
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
    yield log(f"Scanning open redirects on {target}")
    payload = "https://evil.com"

    for param in REDIRECT_PARAMS:
        url = f"{target}?{param}={payload}"
        yield log(f"Testing {url}")
        try:
            r = requests.get(url, headers=HEADERS, timeout=8, allow_redirects=False)
            loc = r.headers.get("Location", "")
            if "evil.com" in loc:
                yield finding(url, param, "medium",
                              f"Open redirect via parameter '{param}' → {loc}",
                              _redirect_report(url, param, loc))
        except Exception as e:
            yield log(f"[ERR] {e}")

    yield log("Open redirect scan complete.")


# ── Clickjacking ──────────────────────────────────────────────────────────────

def scan_clickjacking(target: str, options: dict):
    yield log(f"Scanning clickjacking on {target}")
    try:
        r = requests.get(target, headers=HEADERS, timeout=10)
        xfo = r.headers.get("X-Frame-Options", "")
        csp = r.headers.get("Content-Security-Policy", "")

        if not xfo and "frame-ancestors" not in csp.lower():
            yield finding(target, "missing headers", "medium",
                          "No X-Frame-Options or CSP frame-ancestors — clickjacking possible",
                          _clickjack_report(target))
        else:
            yield log(f"Protected: X-Frame-Options={xfo}, CSP frame-ancestors present={bool('frame-ancestors' in csp.lower())}")
    except Exception as e:
        yield log(f"[ERR] {e}")

    yield log("Clickjacking scan complete.")


# ── DNS Zone Transfer ─────────────────────────────────────────────────────────

def scan_dns_zone_transfer(target: str, options: dict):
    yield log(f"Attempting DNS zone transfer on {target}")
    try:
        ns_answers = dns.resolver.resolve(target, "NS")
        for ns in ns_answers:
            ns_str = str(ns).rstrip(".")
            yield log(f"Trying AXFR on {ns_str}")
            try:
                zone = dns.query.xfr(ns_str, target, timeout=10)
                z = dns.zone.from_xfr(zone)
                records = [str(n) for n in z.nodes.keys()]
                yield finding(target, ns_str, "high",
                              f"Zone transfer succeeded — {len(records)} records exposed",
                              _zone_transfer_report(target, ns_str, records))
            except Exception as e:
                yield log(f"{ns_str} — refused: {e}")
    except Exception as e:
        yield log(f"[ERR] {e}")

    yield log("Zone transfer scan complete.")


# ── SPF / DMARC ───────────────────────────────────────────────────────────────

def scan_spf_dmarc(target: str, options: dict):
    yield log(f"Checking SPF/DMARC for {target}")

    # SPF
    try:
        txt = dns.resolver.resolve(target, "TXT")
        spf_records = [r.to_text() for r in txt if "v=spf1" in r.to_text().lower()]
        if not spf_records:
            yield finding(target, "SPF", "medium",
                          "No SPF record found — email spoofing possible",
                          _email_spoof_report(target, "SPF"))
        else:
            yield log(f"SPF: {spf_records[0]}")
            if "+all" in spf_records[0]:
                yield finding(target, "SPF", "high",
                              "SPF uses +all — accepts all senders",
                              _email_spoof_report(target, "SPF +all"))
    except Exception as e:
        yield log(f"[ERR] SPF: {e}")

    # DMARC
    try:
        dmarc = dns.resolver.resolve(f"_dmarc.{target}", "TXT")
        records = [r.to_text() for r in dmarc]
        yield log(f"DMARC: {records[0] if records else 'none'}")
        if not records:
            yield finding(target, "DMARC", "medium",
                          "No DMARC record — email spoofing not mitigated",
                          _email_spoof_report(target, "DMARC"))
        elif "p=none" in records[0].lower():
            yield finding(target, "DMARC", "low",
                          "DMARC policy is p=none — monitoring only, no enforcement",
                          _email_spoof_report(target, "DMARC p=none"))
    except Exception as e:
        yield log(f"[ERR] DMARC: {e}")

    yield log("SPF/DMARC scan complete.")


# ── Rate Limit ────────────────────────────────────────────────────────────────

def scan_rate_limit(target: str, options: dict):
    yield log(f"Testing rate limiting on {target}")
    count = options.get("requests", 30)

    codes = []
    for i in range(count):
        try:
            r = requests.post(target, json={"test": i}, headers=HEADERS, timeout=5)
            codes.append(r.status_code)
            yield log(f"Request {i+1}: {r.status_code}")
        except Exception as e:
            yield log(f"[ERR] {e}")

    if 429 not in codes:
        yield finding(target, "rate-limit", "medium",
                      f"No rate limiting detected after {count} requests — all returned {set(codes)}",
                      _ratelimit_report(target, count))
    else:
        yield log(f"Rate limiting active — 429 received after {codes.index(429)+1} requests")

    yield log("Rate limit scan complete.")


# ── Helpers ───────────────────────────────────────────────────────────────────

def log(msg: str) -> dict:
    return {"type": "log", "message": msg, "timestamp": datetime.utcnow().isoformat()}

def finding(asset, detail, severity, description, h1_report) -> dict:
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
    for provider in TAKEOVER_FINGERPRINTS:
        if provider in cname:
            return provider
    return "unknown"

def _dns_brute(target: str):
    wordlist = ["www", "dev", "staging", "api", "mail", "blog", "admin",
                "test", "cdn", "static", "assets", "app", "portal"]
    results = []
    for word in wordlist:
        sub = f"{word}.{target}"
        try:
            dns.resolver.resolve(sub, "A")
            results.append(sub)
        except Exception:
            pass
    return results


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
