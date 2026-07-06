#!/usr/bin/env python3
"""
sysload_audit.py - Audit complet d'un agent Sysload UNIX-Agent
Bibliotheque standard uniquement (aucune dependance externe).
Version corrigee : gere les pages d'erreur "200 unauthorized".

Usage AUTORISE uniquement : pentest avec permission ecrite ou CTF/lab.
"""

import argparse
import base64
import hashlib
import difflib
import socket
import ssl
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------

DEFAULT_CREDS = [
    ("admin", "admin"), ("admin", "password"), ("admin", "sysload"),
    ("sysload", "sysload"), ("sysload", "admin"), ("sysload", ""),
    ("root", "root"), ("root", "sysload"), ("root", "toor"),
    ("administrator", "administrator"), ("agent", "agent"),
    ("monitor", "monitor"), ("admin", ""), ("supervision", "supervision"),
]

COMMON_PATHS = [
    "/", "/status", "/stats", "/version", "/info", "/config",
    "/admin", "/login", "/api", "/api/v1", "/metrics", "/health",
    "/cgi-bin/", "/data", "/agent", "/sysload", "/monitor",
    "/perf", "/system", "/cpu", "/memory", "/processes", "/help",
    "/debug", "/test", "/console", "/cmd", "/exec", "/command",
]

# Mots-cles indiquant un echec d'authentification / acces refuse
FAIL_KEYWORDS = [
    "unauthorized", "not authorized", "unauthorised", "access denied",
    "forbidden", "authentication required", "auth required",
    "permission denied", "login required", "not allowed", "invalid",
]

# ------------------------------------------------------------------
# Utilitaires
# ------------------------------------------------------------------

class Result:
    def __init__(self):
        self.lines = []
    def log(self, msg):
        print(msg)
        self.lines.append(msg)
    def save(self, path):
        with open(path, "w") as f:
            f.write("\n".join(self.lines))

def build_base(ip, port, ssl_on):
    scheme = "https" if ssl_on else "http"
    return f"{scheme}://{ip}:{port}"

def make_ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def http_request(url, method="GET", auth=None, timeout=8, data=None):
    """Retourne (status, headers_dict, body_str, err)."""
    req = urllib.request.Request(url, method=method, data=data)
    req.add_header("User-Agent", "sysload-audit/1.0")
    if auth:
        token = base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    ctx = make_ctx()
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        body = resp.read().decode("utf-8", errors="replace")
        return resp.status, dict(resp.headers), body, None
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, dict(e.headers), body, None
    except Exception as e:
        return None, {}, "", str(e)

def body_hash(body):
    return hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest()

def looks_like_failure(body):
    """True si le body contient un mot-cle d'echec d'auth."""
    low = body.lower()
    return any(kw in low for kw in FAIL_KEYWORDS)

def similarity(a, b):
    """Ratio de similarite 0..1 entre deux textes (rapide, tronque)."""
    return difflib.SequenceMatcher(None, a[:4000], b[:4000]).ratio()

# ------------------------------------------------------------------
# Baseline : capturer la page d'erreur/refus de reference
# ------------------------------------------------------------------

class Baseline:
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.hash = body_hash(body)
        self.length = len(body)
        self.is_failure_page = looks_like_failure(body)

    def matches(self, body, threshold=0.98):
        """True si 'body' correspond a la page d'erreur de reference."""
        if body_hash(body) == self.hash:
            return True
        return similarity(self.body, body) >= threshold

# ------------------------------------------------------------------
# Modules d'audit
# ------------------------------------------------------------------

def banner(res, ip, port, ssl_on):
    res.log("=" * 70)
    res.log(" AUDIT SYSLOAD UNIX-AGENT")
    res.log(f" Cible   : {ip}:{port}  (SSL={'oui' if ssl_on else 'non'})")
    res.log(f" Date    : {datetime.now().isoformat()}")
    res.log("=" * 70)

def check_tcp(res, ip, port):
    res.log("\n[1] Test de connectivite TCP")
    try:
        t0 = time.time()
        s = socket.create_connection((ip, port), timeout=8)
        dt = (time.time() - t0) * 1000
        s.close()
        res.log(f"  [+] Port {port} OUVERT ({dt:.0f} ms)")
        return True
    except Exception as e:
        res.log(f"  [-] Port {port} injoignable : {e}")
        return False

def grab_raw_banner(res, ip, port, ssl_on):
    res.log("\n[2] Banniere brute (raw socket)")
    try:
        raw = socket.create_connection((ip, port), timeout=8)
        if ssl_on:
            raw = make_ctx().wrap_socket(raw, server_hostname=ip)
        probe = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
        raw.sendall(probe.encode())
        data = b""
        raw.settimeout(5)
        try:
            while len(data) < 4096:
                chunk = raw.recv(1024)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        raw.close()
        text = data.decode("utf-8", errors="replace")
        for line in text.splitlines()[:25]:
            res.log(f"    {line}")
    except Exception as e:
        res.log(f"  [-] Erreur : {e}")

def establish_baseline(res, base):
    """Capture la page de reference (sans auth + creds bidons)."""
    res.log("\n[3] Etablissement de la baseline (page d'erreur/refus)")
    status, headers, body, err = http_request(base + "/")
    if err:
        res.log(f"  [-] Erreur : {err}")
        return None
    bl = Baseline(status, body)
    res.log(f"  [*] Statut baseline    : HTTP {bl.status}")
    res.log(f"  [*] Taille baseline    : {bl.length} octets")
    res.log(f"  [*] Hash (sha256)      : {bl.hash[:16]}...")
    res.log(f"  [*] Page d'echec/refus : {'OUI' if bl.is_failure_page else 'non detecte'}")

    # Confirmer avec des creds bidons aleatoires
    status2, _, body2, _ = http_request(base + "/", auth=("zzq_fake_9x", "zzq_bogus_7y"))
    if status2 is not None:
        same = bl.matches(body2)
        res.log(f"  [*] Test creds bidons  : HTTP {status2}, identique baseline={same}")
        if not same and not looks_like_failure(body2):
            res.log("  [!] ATTENTION : creds bidons donnent une page differente -> a verifier")

    for k, v in headers.items():
        if k.lower() in ("server", "www-authenticate", "content-type"):
            res.log(f"    {k}: {v}")
    return bl

def enum_paths(res, base, bl):
    res.log("\n[4] Enumeration des endpoints (comparaison au contenu baseline)")
    found = []
    for path in COMMON_PATHS:
        status, headers, body, err = http_request(base + path, timeout=5)
        if err:
            continue
        if status is None:
            continue

        same_as_baseline = bl.matches(body) if bl else False
        is_fail = looks_like_failure(body)
        sim = similarity(bl.body, body) if bl else 0.0

        # On ne signale ACCESSIBLE que si :
        #   - le contenu differe reellement de la page d'erreur
        #   - ET ne contient pas de mot-cle d'echec
        if status == 404:
            continue
        if same_as_baseline or is_fail:
            # meme page d'erreur -> on ignore (ou log discret)
            res.log(f"  [{status}] {path}  (refus/identique baseline, sim={sim:.2f})")
            continue

        # Contenu different + pas de mot d'echec = vraiment interessant
        note = "  <<< CONTENU DIFFERENT - A INSPECTER"
        res.log(f"  [{status}] {path}  (taille={len(body)}, sim={sim:.2f}){note}")
        found.append((path, body))

    if not found:
        res.log("  [i] Aucun endpoint ne differe de la page d'erreur (tout est protege)")
    return found

def test_creds(res, base, bl):
    res.log("\n[5] Test de credentials (comparaison de CONTENU, pas taille)")
    if bl is None:
        res.log("  [-] Pas de baseline, test impossible")
        return []
    hits = []
    for user, pwd in DEFAULT_CREDS:
        status, headers, body, err = http_request(base + "/", auth=(user, pwd))
        if err:
            res.log(f"  [!] {user}:{pwd} -> erreur {err}")
            continue

        same = bl.matches(body)
        is_fail = looks_like_failure(body)
        sim = similarity(bl.body, body)

        if same or is_fail:
            res.log(f"  [{status}] {user}:{pwd}  (refuse, sim={sim:.2f})")
        else:
            # Contenu different ET pas de message d'echec = succes probable
            res.log(f"  [{status}] {user}:{pwd}  (sim={sim:.2f})  <<< POSSIBLE SUCCES")
            hits.append((user, pwd, status))

    if hits:
        res.log("\n  [+] Credentials potentiellement valides :")
        for u, p, s in hits:
            res.log(f"      {u}:{p}  (HTTP {s})")
    else:
        res.log("  [i] Aucun credential ne change le contenu -> tous refuses")
    return hits

def check_methods(res, base, bl):
    res.log("\n[6] Methodes HTTP (OPTIONS/TRACE/PUT/DELETE)")
    for method in ("OPTIONS", "TRACE", "PUT", "DELETE"):
        status, headers, body, err = http_request(base + "/", method=method)
        if err:
            res.log(f"  [{method}] erreur : {err}")
            continue
        allow = headers.get("Allow", "")
        note = ""
        if method == "TRACE" and status == 200 and "TRACE" in body.upper():
            note = "  <<< TRACE actif (XST possible)"
        if method == "PUT" and status in (200, 201, 204):
            note = "  <<< PUT autorise (upload ?)"
        res.log(f"  [{status}] {method}  {('Allow: '+allow) if allow else ''}{note}")

def check_info_leak(res, found):
    res.log("\n[7] Recherche de fuites dans les endpoints REELLEMENT accessibles")
    if not found:
        res.log("  [i] Aucun endpoint accessible a analyser")
        return
    keywords = ["password", "passwd", "root", "kernel", "linux", "version",
                "cpu", "memory", "process", "user", "config", "path",
                "/etc/", "/home/", "id_rsa", "secret", "token", "hostname"]
    leaked = False
    for path, body in found:
        low = body.lower()
        hits = [k for k in keywords if k in low]
        if hits:
            leaked = True
            res.log(f"  [!] {path} contient : {', '.join(sorted(set(hits)))}")
            for kw in hits[:3]:
                idx = low.find(kw)
                snippet = body[max(0, idx-30):idx+50].replace("\n", " ")
                res.log(f"       ...{snippet}...")
    if not leaked:
        res.log("  [i] Pas de fuite evidente")

def summary(res, ssl_on):
    res.log("\n" + "=" * 70)
    res.log(" RESUME / PISTES")
    res.log("=" * 70)
    res.log(" - CentOS/RHEL 6 = EOL (aucun patch) -> criticite haute")
    res.log(" - Kernel 2.6.32 -> DirtyCOW (CVE-2016-5195) si shell obtenu")
    if not ssl_on:
        res.log(" - Trafic en clair -> interception possible")
    res.log(" - Verifier restriction par IP (collecteur central autorise)")
    res.log(" - Chercher creds par defaut Sysload (OpenText)")

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Audit Sysload UNIX-Agent (stdlib, gere pages 200-unauthorized)")
    parser.add_argument("-i", "--ip", required=True, help="IP ou hostname cible")
    parser.add_argument("-p", "--port", type=int, default=9501, help="Port (defaut 9501)")
    parser.add_argument("-s", "--ssl", choices=["true", "false"], default="false",
                        help="Utiliser SSL/HTTPS (defaut false)")
    parser.add_argument("-o", "--output", help="Fichier de rapport (optionnel)")
    args = parser.parse_args()

    ssl_on = args.ssl.lower() == "true"
    base = build_base(args.ip, args.port, ssl_on)
    res = Result()

    banner(res, args.ip, args.port, ssl_on)

    if not check_tcp(res, args.ip, args.port):
        res.log("\n[!] Service injoignable, arret.")
        if args.output:
            res.save(args.output)
        sys.exit(1)

    grab_raw_banner(res, args.ip, args.port, ssl_on)
    bl = establish_baseline(res, base)
    found = enum_paths(res, base, bl)
    test_creds(res, base, bl)
    check_methods(res, base, bl)
    check_info_leak(res, found)
    summary(res, ssl_on)

    if args.output:
        res.save(args.output)
        print(f"\n[+] Rapport sauvegarde dans {args.output}")

if __name__ == "__main__":
    main()
