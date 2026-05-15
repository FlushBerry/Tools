#!/usr/bin/env python3
"""
Analyse un fichier .nmap pour identifier les services HTTP (non-HTTPS)
exposant une authentification ou un service sensible.
Aucune dépendance externe (stdlib uniquement).
"""

import sys
import re
import socket
import urllib.request
import urllib.error
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

LOG_FILE = "http_test.txt"
TIMEOUT = 6
MAX_WORKERS = 20

INTERESTING_SIGNATURES = [
    ("Basic Auth",           re.compile(r"WWW-Authenticate:\s*Basic", re.I), "HIGH"),
    ("Digest Auth",          re.compile(r"WWW-Authenticate:\s*Digest", re.I), "HIGH"),
    ("NTLM Auth",            re.compile(r"WWW-Authenticate:\s*(NTLM|Negotiate)", re.I), "HIGH"),
    ("Login form",           re.compile(r"<input[^>]+type=[\"']?password", re.I), "HIGH"),
    ("Login keyword",        re.compile(r"\b(login|sign in|log in|authentification|connexion)\b", re.I), "MEDIUM"),
    ("Admin panel",          re.compile(r"\b(admin|administrator|administration)\b", re.I), "MEDIUM"),
    ("Jenkins",              re.compile(r"jenkins", re.I), "HIGH"),
    ("GitLab",               re.compile(r"gitlab", re.I), "HIGH"),
    ("Gitea",                re.compile(r"gitea", re.I), "HIGH"),
    ("Tomcat Manager",       re.compile(r"tomcat|catalina", re.I), "HIGH"),
    ("JBoss",                re.compile(r"jboss|wildfly", re.I), "HIGH"),
    ("phpMyAdmin",           re.compile(r"phpmyadmin", re.I), "HIGH"),
    ("Adminer",              re.compile(r"adminer", re.I), "HIGH"),
    ("Webmin",               re.compile(r"webmin", re.I), "HIGH"),
    ("cPanel",               re.compile(r"cpanel", re.I), "HIGH"),
    ("Plesk",                re.compile(r"plesk", re.I), "HIGH"),
    ("Grafana",              re.compile(r"grafana", re.I), "HIGH"),
    ("Kibana",               re.compile(r"kibana", re.I), "HIGH"),
    ("Elasticsearch",        re.compile(r"elasticsearch|\"cluster_name\"", re.I), "HIGH"),
    ("Jupyter",              re.compile(r"jupyter", re.I), "HIGH"),
    ("Portainer",            re.compile(r"portainer", re.I), "HIGH"),
    ("Rancher",              re.compile(r"rancher", re.I), "HIGH"),
    ("Kubernetes Dashboard", re.compile(r"kubernetes.*dashboard", re.I), "HIGH"),
    ("RabbitMQ",             re.compile(r"rabbitmq", re.I), "HIGH"),
    ("Nexus Repo",           re.compile(r"nexus repository", re.I), "HIGH"),
    ("SonarQube",            re.compile(r"sonarqube|sonar", re.I), "MEDIUM"),
    ("Confluence",           re.compile(r"confluence", re.I), "HIGH"),
    ("Jira",                 re.compile(r"jira", re.I), "HIGH"),
    ("Bitbucket",            re.compile(r"bitbucket", re.I), "HIGH"),
    ("WordPress",            re.compile(r"wp-content|wordpress", re.I), "MEDIUM"),
    ("Drupal",               re.compile(r"drupal", re.I), "MEDIUM"),
    ("Joomla",               re.compile(r"joomla", re.I), "MEDIUM"),
    ("Zabbix",               re.compile(r"zabbix", re.I), "HIGH"),
    ("Nagios",               re.compile(r"nagios", re.I), "HIGH"),
    ("Splunk",               re.compile(r"splunk", re.I), "HIGH"),
    ("VNC over HTTP",        re.compile(r"vnc", re.I), "HIGH"),
    ("Router/IoT",           re.compile(r"router|firmware|tp-link|d-link|netgear|cisco|mikrotik", re.I), "MEDIUM"),
    ("Printer",              re.compile(r"printer|hp laserjet|brother|epson|canon", re.I), "MEDIUM"),
    ("Camera/IPCam",         re.compile(r"webcam|ipcam|hikvision|dahua|axis|camera", re.I), "HIGH"),
    ("API endpoint",         re.compile(r"swagger|openapi|graphql", re.I), "MEDIUM"),
    ("Directory listing",    re.compile(r"<title>Index of /|Directory listing for", re.I), "MEDIUM"),
    ("Default page",         re.compile(r"it works!|welcome to nginx|apache2 ubuntu default|iis windows", re.I), "LOW"),
]


def log(msg, fh=None):
    print(msg)
    if fh:
        fh.write(msg + "\n")
        fh.flush()


def parse_nmap(path):
    targets = []
    current_host = None
    host_re = re.compile(r"Nmap scan report for (.+)")
    port_re = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)(.*)$")

    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.rstrip()
            m = host_re.search(line)
            if m:
                h = m.group(1).strip()
                ip_m = re.search(r"\(([\d\.]+)\)", h)
                current_host = ip_m.group(1) if ip_m else h.split()[0]
                continue
            m = port_re.match(line)
            if m and current_host:
                port, svc, rest = m.group(1), m.group(2).lower(), m.group(3).lower()
                full = svc + " " + rest
                if "http" in full and "https" not in full and "ssl" not in full:
                    targets.append((current_host, int(port)))
    return targets


def fetch(host, port):
    url = f"http://{host}:{port}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 recon"})
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, req, fp, code, msg, headers, newurl):
                return None
        opener = urllib.request.build_opener(NoRedirect)
        try:
            resp = opener.open(req, timeout=TIMEOUT)
            return resp.status, str(resp.headers), resp.read(65536).decode("utf-8", errors="ignore"), resp.url, None
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read(65536).decode("utf-8", errors="ignore")
            except Exception:
                pass
            return e.code, str(e.headers), body, url, None
    except (socket.timeout, TimeoutError):
        return None, "", "", url, "timeout"
    except (ConnectionRefusedError, ConnectionResetError) as e:
        return None, "", "", url, f"conn: {e}"
    except Exception as e:
        return None, "", "", url, f"err: {type(e).__name__}: {e}"


def analyze(host, port):
    status, headers, body, final_url, err = fetch(host, port)
    result = {
        "host": host, "port": port, "url": f"http://{host}:{port}/",
        "status": status, "error": err, "findings": [],
        "title": None, "server": None, "redirect_https": False,
    }
    if err:
        return result

    loc = ""
    for line in headers.splitlines():
        if line.lower().startswith("location:"):
            loc = line.split(":", 1)[1].strip()
            break
    if loc.lower().startswith("https://"):
        result["redirect_https"] = True
        return result

    for line in headers.splitlines():
        if line.lower().startswith("server:"):
            result["server"] = line.split(":", 1)[1].strip()
            break

    tm = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    if tm:
        result["title"] = re.sub(r"\s+", " ", tm.group(1)).strip()[:200]

    haystack = headers + "\n" + body
    seen = set()
    for label, rx, sev in INTERESTING_SIGNATURES:
        if rx.search(haystack) and label not in seen:
            result["findings"].append((sev, label))
            seen.add(label)

    if status in (401, 407):
        result["findings"].append(("HIGH", f"Auth required (HTTP {status})"))
    elif status == 403:
        result["findings"].append(("MEDIUM", "Forbidden (HTTP 403)"))

    return result


def severity_rank(findings):
    order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    return max((order.get(s, 0) for s, _ in findings), default=0)


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <fichier.nmap>")
        sys.exit(1)

    nmap_file = sys.argv[1]
    fh = open(LOG_FILE, "w")

    log("=" * 60, fh)
    log(f"Date: {datetime.now()}", fh)
    log(f"Fichier nmap: {nmap_file}", fh)
    log("=" * 60, fh)

    log("\n[ETAPE 1] Extraction des host:port HTTP...", fh)
    targets = parse_nmap(nmap_file)
    log(f"  -> {len(targets)} cibles trouvées", fh)
    for h, p in targets:
        log(f"   - {h}:{p}", fh)

    if not targets:
        log("Aucune cible. Fin.", fh)
        return

    log("\n[ETAPE 2] Analyse HTTP (parallèle)...", fh)
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(analyze, h, p): (h, p) for h, p in targets}
        for fut in as_completed(futs):
            r = fut.result()
            results.append(r)
            if r["error"]:
                log(f"  [DOWN]  {r['url']} ({r['error']})", fh)
            elif r["redirect_https"]:
                log(f"  [HTTPS] {r['url']} redirige vers HTTPS", fh)
            else:
                tags = ",".join(f"{s}:{l}" for s, l in r["findings"]) or "-"
                log(f"  [OK]    {r['url']} [{r['status']}] server={r['server']} title={r['title']!r} :: {tags}", fh)

    log("\n" + "=" * 60, fh)
    log("[DETAIL] Cibles HTTP sensibles (tri par sévérité)", fh)
    log("=" * 60, fh)

    valid = [r for r in results if not r["error"] and not r["redirect_https"]]
    valid.sort(key=lambda r: severity_rank(r["findings"]), reverse=True)

    high   = [r for r in valid if any(s == "HIGH"   for s, _ in r["findings"])]
    medium = [r for r in valid if r not in high and any(s == "MEDIUM" for s, _ in r["findings"])]
    low    = [r for r in valid if r not in high and r not in medium and r["findings"]]
    empty  = [r for r in valid if not r["findings"]]
    down   = [r for r in results if r["error"]]
    https  = [r for r in results if r["redirect_https"]]

    def dump_detail(title, items):
        log(f"\n--- {title} ({len(items)}) ---", fh)
        for r in items:
            log(f"  {r['url']}  [{r['status']}]", fh)
            if r["server"]:
                log(f"     Server: {r['server']}", fh)
            if r["title"]:
                log(f"     Title:  {r['title']}", fh)
            for sev, label in r["findings"]:
                log(f"     [{sev}] {label}", fh)

    dump_detail("HIGH - Authentification / Service sensible exposé en clair", high)
    dump_detail("MEDIUM - Suspect", medium)
    dump_detail("LOW - Pages par défaut", low)
    dump_detail("Sans signature notable", empty)

    # ============================================
    # RECAP FINAL : URLs uniquement, par catégorie
    # ============================================
    log("\n" + "=" * 60, fh)
    log("[RECAP] URLs par catégorie", fh)
    log("=" * 60, fh)

    def dump_urls(title, items):
        log(f"\n# {title} ({len(items)})", fh)
        for r in items:
            log(r["url"], fh)

    dump_urls("HIGH",              high)
    dump_urls("MEDIUM",            medium)
    dump_urls("LOW",               low)
    dump_urls("NO_SIGNATURE",      empty)
    dump_urls("REDIRECT_HTTPS",    https)
    dump_urls("DOWN/UNREACHABLE",  down)

    log("\n" + "=" * 60, fh)
    log(f"Résultats dans {LOG_FILE}", fh)
    fh.close()


if __name__ == "__main__":
    main()
