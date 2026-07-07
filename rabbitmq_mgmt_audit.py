#!/usr/bin/env python3
"""
rabbitmq_mgmt_audit.py — Auditeur de l'API RabbitMQ Management
Usage:
  python3 rabbitmq_mgmt_audit.py -t http://10.0.0.5:15672
  python3 rabbitmq_mgmt_audit.py -f targets.txt -o report.json

Objectif: recon + tests de sécurité non-destructifs sur l'API Management RabbitMQ.
À n'utiliser QUE sur des cibles explicitement autorisées.
"""

import argparse
import json
import sys
import base64
import urllib.request
import urllib.error
import urllib.parse
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed


# ------------------------------------------------------------------ #
#  Couleurs / logging
# ------------------------------------------------------------------ #
class C:
    G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"
    B = "\033[94m"; M = "\033[95m"; W = "\033[97m"; X = "\033[0m"

def log(sym, msg, col=C.W):
    print(f"{col}[{sym}]{C.X} {msg}")

def info(m): log("*", m, C.B)
def good(m): log("+", m, C.G)
def warn(m): log("!", m, C.Y)
def bad(m):  log("-", m, C.R)


# ------------------------------------------------------------------ #
#  Résultats globaux
# ------------------------------------------------------------------ #
RESULTS = {"targets": []}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SEV_COL = {"CRITICAL": C.R, "HIGH": C.R, "MEDIUM": C.Y, "LOW": C.B, "INFO": C.W}


# ------------------------------------------------------------------ #
#  Credentials par défaut (guest:guest en premier, toujours testé)
# ------------------------------------------------------------------ #
DEFAULT_CREDS = [
    ("guest", "guest"),
    ("admin", "admin"),
    ("administrator", "administrator"),
    ("admin", "password"),
    ("rabbitmq", "rabbitmq"),
    ("rabbit", "rabbit"),
    ("admin", "changeme"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
    ("guest", ""),
    ("admin", "guest"),
]


# ------------------------------------------------------------------ #
#  HTTP helper
# ------------------------------------------------------------------ #
def _ctx():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def http_get(url, user=None, password=None, timeout=8):
    """GET → (status_code, body_str, headers_dict)."""
    req = urllib.request.Request(url, method="GET")
    req.add_header("User-Agent", "rmq-mgmt-audit/1.0")
    if user is not None:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as e:
        return None, str(e), {}


# ------------------------------------------------------------------ #
#  Audit d'une cible
# ------------------------------------------------------------------ #
def audit_target(base):
    base = base.rstrip("/")
    res = {"target": base, "reachable": False, "valid_creds": [],
           "findings": [], "info": {}}

    def finding(sev, title, detail):
        res["findings"].append({"severity": sev, "title": title, "detail": detail})

    print("\n" + "=" * 60)
    print(f"{C.M}  CIBLE: {base}{C.X}")
    print("=" * 60)

    # --- 1. Accessibilité + fingerprint non authentifié
    code, body, hdrs = http_get(f"{base}/api/overview")
    if code is None:
        bad(f"Injoignable: {body}")
        RESULTS["targets"].append(res)
        return res
    res["reachable"] = True
    good(f"API Management joignable (HTTP {code})")

    # En-têtes de sécurité
    lower = {k.lower(): v for k, v in hdrs.items()}
    for h, msg in {
        "strict-transport-security": "HSTS manquant",
        "content-security-policy": "CSP manquant",
        "x-frame-options": "X-Frame-Options manquant (clickjacking)",
        "x-content-type-options": "X-Content-Type-Options manquant",
    }.items():
        if h not in lower:
            warn(f"  {msg}")
            finding("LOW", msg, f"En-tête {h} absent.")
    if "server" in lower:
        info(f"  Server: {lower['server']}")

    # --- 2. Test systématique des credentials par défaut
    info("Test des credentials par défaut (guest:guest en priorité)...")
    for user, pwd in DEFAULT_CREDS:
        code, body, _ = http_get(f"{base}/api/whoami", user, pwd)
        if code == 200:
            tags = ""
            try:
                tags = json.loads(body).get("tags", "")
            except Exception:
                pass
            marker = "  <== ADMIN" if "administrator" in str(tags) else ""
            good(f"  VALIDE: {user}:{pwd or '(vide)'} (tags={tags}){marker}")
            res["valid_creds"].append({"user": user, "password": pwd, "tags": tags})
            sev = "CRITICAL" if "administrator" in str(tags) else "HIGH"
            finding(sev, f"Credential par défaut valide: {user}:{pwd or '(vide)'}",
                    f"Accès à l'API Management avec tags={tags}.")
        elif code == 401:
            pass  # invalide, silencieux
        elif code is None:
            break

    if not res["valid_creds"]:
        good("  Aucun credential par défaut valide.")
        RESULTS["targets"].append(res)
        return res

    # --- 3. Dump avec le meilleur credential (admin en priorité)
    best = sorted(res["valid_creds"],
                  key=lambda c: 0 if "administrator" in str(c["tags"]) else 1)[0]
    u, p = best["user"], best["password"]
    info(f"Extraction d'informations avec {u}:{p or '(vide)'}...")
    dump_info(base, u, p, res, finding)

    RESULTS["targets"].append(res)
    return res


# ------------------------------------------------------------------ #
#  Extraction d'informations (авec credential valide)
# ------------------------------------------------------------------ #
def dump_info(base, user, pwd, res, finding):
    # Overview → version, node
    code, body, _ = http_get(f"{base}/api/overview", user, pwd)
    if code == 200:
        try:
            ov = json.loads(body)
            ver = ov.get("rabbitmq_version") or ov.get("product_version")
            erlang = ov.get("erlang_version")
            info(f"  RabbitMQ version: {ver} | Erlang: {erlang}")
            res["info"]["version"] = ver
            res["info"]["erlang"] = erlang
            res["info"]["node"] = ov.get("node")
        except Exception:
            pass

    # Users + tags
    code, body, _ = http_get(f"{base}/api/users", user, pwd)
    if code == 200:
        try:
            users = json.loads(body)
            res["info"]["users"] = []
            for us in users:
                tags = us.get("tags", "")
                marker = "  <== ADMIN" if "administrator" in str(tags) else ""
                info(f"    User: {us.get('name')} (tags={tags}){marker}")
                res["info"]["users"].append({"name": us.get("name"), "tags": tags})
        except Exception:
            pass

    # Definitions → hashes de mots de passe (fuite critique)
    code, body, _ = http_get(f"{base}/api/definitions", user, pwd)
    if code == 200:
        try:
            defs = json.loads(body)
            hashed = [u for u in defs.get("users", []) if u.get("password_hash")]
            if hashed:
                warn(f"  /api/definitions expose {len(hashed)} hash(es) de mot de passe")
                for h in hashed:
                    info(f"    {h.get('name')}: {h.get('password_hash','')[:24]}... "
                         f"(algo={h.get('hashing_algorithm','?')})")
                finding("HIGH", "Fuite des hash de mots de passe via /api/definitions",
                        "Un compte management peut exporter tous les hash utilisateurs.")
            res["info"]["definitions_users"] = len(defs.get("users", []))
        except Exception:
            pass

    # Vhosts
    code, body, _ = http_get(f"{base}/api/vhosts", user, pwd)
    if code == 200:
        try:
            vhosts = [v.get("name") for v in json.loads(body)]
            info(f"  Vhosts: {', '.join(vhosts)}")
            res["info"]["vhosts"] = vhosts
        except Exception:
            pass

    # Permissions
    code, body, _ = http_get(f"{base}/api/permissions", user, pwd)
    if code == 200:
        try:
            perms = json.loads(body)
            res["info"]["permissions"] = []
            for pm in perms:
                info(f"    Perm: user={pm.get('user')} vhost={pm.get('vhost')} "
                     f"configure={pm.get('configure')} write={pm.get('write')} "
                     f"read={pm.get('read')}")
                res["info"]["permissions"].append({
                    "user": pm.get("user"), "vhost": pm.get("vhost"),
                    "configure": pm.get("configure"),
                    "write": pm.get("write"), "read": pm.get("read"),
                })
            # Détection de permissions trop larges
            wide = [p for p in perms
                    if p.get("configure") == ".*" and p.get("write") == ".*"
                    and p.get("read") == ".*"]
            if wide:
                finding("MEDIUM", "Permissions trop permissives (.* / .* / .*)",
                        f"{len(wide)} attribution(s) accordent un accès total sur un vhost.")
        except Exception:
            pass

    # Connexions actives (fuite de topologie / IPs clientes)
    code, body, _ = http_get(f"{base}/api/connections", user, pwd)
    if code == 200:
        try:
            conns = json.loads(body)
            if conns:
                info(f"  Connexions actives: {len(conns)}")
                for cn in conns[:10]:
                    info(f"    {cn.get('peer_host')}:{cn.get('peer_port')} "
                         f"user={cn.get('user')} proto={cn.get('protocol')}")
                res["info"]["connections"] = len(conns)
        except Exception:
            pass

    # Channels
    code, body, _ = http_get(f"{base}/api/channels", user, pwd)
    if code == 200:
        try:
            chans = json.loads(body)
            res["info"]["channels"] = len(chans)
            if chans:
                info(f"  Channels actifs: {len(chans)}")
        except Exception:
            pass

    # Exchanges
    code, body, _ = http_get(f"{base}/api/exchanges", user, pwd)
    if code == 200:
        try:
            exs = json.loads(body)
            res["info"]["exchanges"] = len(exs)
            info(f"  Exchanges: {len(exs)}")
        except Exception:
            pass

    # Queues (avec contenu de messages potentiel)
    code, body, _ = http_get(f"{base}/api/queues", user, pwd)
    if code == 200:
        try:
            queues = json.loads(body)
            res["info"]["queues"] = []
            info(f"  Queues: {len(queues)}")
            for q in queues:
                n = q.get("name")
                msgs = q.get("messages", 0)
                vhost = q.get("vhost", "/")
                if msgs:
                    warn(f"    Queue '{n}' (vhost={vhost}) contient {msgs} message(s)")
                res["info"]["queues"].append({"name": n, "vhost": vhost, "messages": msgs})
            # Signalement: messages persistants lisibles via l'API
            with_msgs = [q for q in queues if q.get("messages", 0) > 0]
            if with_msgs:
                finding("MEDIUM", "Messages présents dans des queues, lisibles via l'API",
                        f"{len(with_msgs)} queue(s) contiennent des messages. "
                        "L'API /api/queues/<vhost>/<name>/get permet de les consommer "
                        "(potentielle fuite de données métier).")
        except Exception:
            pass

    # Détection version vulnérable (CVE connues)
    ver = res["info"].get("version")
    if ver:
        check_known_cves(ver, finding)


# ------------------------------------------------------------------ #
#  Vérification de CVE connues selon la version
# ------------------------------------------------------------------ #
def _vtuple(v):
    parts = []
    for x in str(v).split("."):
        num = "".join(ch for ch in x if ch.isdigit())
        parts.append(int(num) if num else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])

def check_known_cves(ver, finding):
    try:
        vt = _vtuple(ver)
    except Exception:
        return
    # Exemples de CVE historiques RabbitMQ (à ajuster selon veille)
    cves = [
        ("CVE-2023-46118", (3, 12, 7), "MEDIUM",
         "Rate-limit non appliqué sur certaines requêtes management → DoS possible."),
        ("CVE-2022-31008", (3, 10, 0), "MEDIUM",
         "Fuite potentielle liée au chiffrement des définitions (versions < 3.10)."),
        ("CVE-2021-32718", (3, 8, 17), "MEDIUM",
         "XSS stockée dans l'UI Management (versions < 3.8.17)."),
        ("CVE-2021-32719", (3, 8, 18), "MEDIUM",
         "XSS via en-tête de connexion dans l'UI Management (< 3.8.18)."),
    ]
    for cve, fixed, sev, desc in cves:
        if vt < fixed:
            warn(f"  Version {ver} potentiellement vulnérable à {cve}")
            finding(sev, f"{cve} (version {ver} < {'.'.join(map(str, fixed))})", desc)


# ------------------------------------------------------------------ #
#  Chargement des cibles
# ------------------------------------------------------------------ #
def load_targets(args):
    targets = []
    if args.target:
        targets.append(args.target.strip())
    if args.file:
        try:
            with open(args.file) as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if not line.startswith("http"):
                        line = "http://" + line
                    targets.append(line)
        except Exception as e:
            bad(f"Impossible de lire le fichier {args.file}: {e}")
            sys.exit(1)
    # Déduplication en conservant l'ordre
    seen, uniq = set(), []
    for t in targets:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


# ------------------------------------------------------------------ #
#  Rapport final
# ------------------------------------------------------------------ #
def print_report(json_out=None):
    print("\n" + "=" * 60)
    print(f"{C.M}  RAPPORT GLOBAL D'AUDIT — RABBITMQ MANAGEMENT{C.X}")
    print("=" * 60)

    total_creds = 0
    all_findings = []
    for t in RESULTS["targets"]:
        total_creds += len(t["valid_creds"])
        for f in t["findings"]:
            all_findings.append((t["target"], f))

    print(f"\nCibles auditées : {len(RESULTS['targets'])}")
    print(f"Cibles avec credentials par défaut valides : "
          f"{sum(1 for t in RESULTS['targets'] if t['valid_creds'])}")
    print(f"Total de credentials valides trouvés : {total_creds}\n")

    if not all_findings:
        good("Aucun finding remonté.")
    else:
        counts = {}
        for _, f in all_findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        summary = "  ".join(
            f"{SEV_COL.get(s, C.W)}{s}: {counts[s]}{C.X}"
            for s in sorted(counts, key=lambda x: SEV_ORDER.get(x, 9))
        )
        print(f"Résumé : {summary}\n")

        all_findings.sort(key=lambda x: SEV_ORDER.get(x[1]["severity"], 9))
        for target, f in all_findings:
            col = SEV_COL.get(f["severity"], C.W)
            print(f"{col}[{f['severity']}]{C.X} {f['title']}")
            print(f"      cible : {target}")
            print(f"      {f['detail']}")

    print("\n" + "=" * 60)
    print(f"{C.M}  RECOMMANDATIONS{C.X}")
    print("=" * 60)
    for r in [
        "Supprimer/renommer le compte 'guest' ou le restreindre à localhost.",
        "Imposer des mots de passe forts (bannir tous les creds par défaut).",
        "Restreindre l'accès à l'API Management (15672) par IP / VPN / mTLS.",
        "Activer HTTPS (15671) avec en-têtes de sécurité (HSTS, CSP, X-Frame-Options).",
        "Appliquer le moindre privilège sur les tags et permissions par vhost.",
        "Ne pas exposer /api/definitions ; surveiller les exports de hash.",
        "Maintenir RabbitMQ à jour pour corriger les CVE connues.",
        "Activer la journalisation et l'alerte sur les connexions à l'API.",
    ]:
        print(f"  - {r}")

    if json_out:
        try:
            with open(json_out, "w") as fh:
                json.dump(RESULTS, fh, indent=2, default=str)
            good(f"Résultats JSON écrits dans : {json_out}")
        except Exception as e:
            bad(f"Impossible d'écrire le JSON : {e}")


# ------------------------------------------------------------------ #
#  CLI / main
# ------------------------------------------------------------------ #
def parse_args():
    p = argparse.ArgumentParser(
        description="Auditeur de l'API RabbitMQ Management (creds par défaut + recon).")
    p.add_argument("-t", "--target",
                   help="Cible unique, ex: http://10.0.0.5:15672")
    p.add_argument("-f", "--file",
                   help="Fichier de cibles (une URL http(s)://host:port par ligne)")
    p.add_argument("-w", "--workers", type=int, default=5,
                   help="Nombre de cibles auditées en parallèle (défaut: 5)")
    p.add_argument("-o", "--output", help="Fichier de sortie JSON")
    return p.parse_args()


def banner():
    print(f"""{C.M}
 ┌───────────────────────────────────────────┐
 │     RabbitMQ Management Audit Tool          │
 │  default-creds · recon · misconfig · CVE    │
 └───────────────────────────────────────────┘{C.X}
 {C.Y}Usage strictement limité aux cibles autorisées.{C.X}
""")


def main():
    banner()
    args = parse_args()

    if not args.target and not args.file:
        bad("Fournir au moins -t <url> ou -f <fichier>.")
        sys.exit(1)

    targets = load_targets(args)
    if not targets:
        bad("Aucune cible valide à auditer.")
        sys.exit(1)

    info(f"{len(targets)} cible(s) à auditer.\n")

    try:
        if len(targets) == 1:
            audit_target(targets[0])
        else:
            with ThreadPoolExecutor(max_workers=args.workers) as ex:
                futures = {ex.submit(audit_target, t): t for t in targets}
                for fut in as_completed(futures):
                    try:
                        fut.result()
                    except Exception as e:
                        bad(f"Erreur sur {futures[fut]} : {e}")
        print_report(args.output)
    except KeyboardInterrupt:
        print()
        warn("Interrompu par l'utilisateur.")
        print_report(args.output)
        sys.exit(130)


if __name__ == "__main__":
    main()

