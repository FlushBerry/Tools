#!/usr/bin/env python3
"""
pgaudit.py - Audit PostgreSQL sans dépendances externes (stdlib only)
Usage:
    python3 pgaudit.py -i 10.0.0.5 -p 5432
    python3 pgaudit.py -i 10.0.0.5:5432
    python3 pgaudit.py -f targets.txt
    python3 pgaudit.py --nmap scan.gnmap
    python3 pgaudit.py -f targets.txt -t 30 -w 20

Éthique: utilise uniquement sur des systèmes que tu possèdes ou pour lesquels
tu as une autorisation écrite. Aucune modification n'est effectuée sur les cibles.
"""

import argparse
import socket
import struct
import hashlib
import hmac
import base64
import os
import re
import ssl
import sys
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------------------
# Constantes protocole
# ---------------------------------------------------------------------------
PROTO_V3 = 196608          # 0x00030000
SSL_REQUEST_CODE = 80877103  # magic SSLRequest

DEFAULT_CREDS = [
    ("postgres", "postgres"),
    ("postgres", ""),
    ("postgres", "password"),
    ("postgres", "admin"),
    ("postgres", "postgres123"),
    ("postgres", "root"),
    ("postgres", "123456"),
    ("admin", "admin"),
    ("root", "root"),
    ("postgres", "changeme"),
    ("postgres", "pgsql"),
    ("pgsql", "pgsql"),
    ("replicator", "replicator"),
    ("odoo", "odoo"),
    ("gitlab", "gitlab"),
    ("keycloak", "keycloak"),
]

DEFAULT_DBS = ["postgres", "template1", "template0"]

# ---------------------------------------------------------------------------
# Base CVE (curée, focus impact réel / RCE / auth bypass)
# ---------------------------------------------------------------------------
CVE_DB = [
    {"cve": "CVE-2019-9193", "range": (9.3, 12.0), "sev": "CRITICAL",
     "title": "COPY TO/FROM PROGRAM -> RCE (feature abuse, superuser)",
     "note": "Si accès superuser: COPY ... FROM PROGRAM 'cmd' donne RCE.",
     "exploit": "COPY (SELECT '') TO PROGRAM 'id'; -- nécessite superuser/pg_execute_server_program"},
    {"cve": "CVE-2018-1058", "range": (9.3, 10.2), "sev": "HIGH",
     "title": "Search_path / public schema privilege escalation",
     "note": "Fonctions dans schema public peuvent détourner exécution superuser.",
     "exploit": "Création objets malicieux dans public schema."},
    {"cve": "CVE-2021-23214", "range": (9.6, 14.1), "sev": "HIGH",
     "title": "Server processes unencrypted bytes after SSL/GSS on trust auth (MITM)",
     "note": "Injection de requêtes en clair après SSL avec auth trust.",
     "exploit": "MITM injection pré-handshake."},
    {"cve": "CVE-2022-1552", "range": (10.0, 14.3), "sev": "HIGH",
     "title": "Autovacuum/REINDEX/CLUSTER security restricted operation bypass",
     "note": "Escalade vers superuser via opérations de maintenance.",
     "exploit": "Objets piégés déclenchés par maintenance superuser."},
    {"cve": "CVE-2024-0985", "range": (12.0, 16.1), "sev": "HIGH",
     "title": "REFRESH MATERIALIZED VIEW CONCURRENTLY - privesc",
     "note": "Exécution de code dans le contexte du propriétaire de la vue.",
     "exploit": "Vue matérialisée piégée."},
    {"cve": "CVE-2024-10977", "range": (12.0, 17.0), "sev": "MEDIUM",
     "title": "Client injection via error messages from untrusted server",
     "note": "Serveur malveillant peut injecter dans le client.",
     "exploit": "Réponses serveur forgées."},
    {"cve": "CVE-2025-1094", "range": (13.0, 17.2), "sev": "CRITICAL",
     "title": "SQL injection via psql quoting (invalid UTF-8) -> RCE via \\! ",
     "note": "Mauvaise gestion quoting -> injection SQL et RCE via meta-command psql.",
     "exploit": "Payload UTF-8 invalide dans identifiants -> SQLi -> \\! shell."},
]

# ---------------------------------------------------------------------------
# Helpers protocole
# ---------------------------------------------------------------------------
def _read_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connexion fermée par le pair")
        buf += chunk
    return buf

def _read_message(sock):
    """Retourne (type_byte, payload)."""
    t = _read_exact(sock, 1)
    length = struct.unpack("!I", _read_exact(sock, 4))[0]
    payload = _read_exact(sock, length - 4) if length > 4 else b""
    return t, payload

def _startup_packet(user, database):
    body = struct.pack("!I", PROTO_V3)
    body += b"user\x00" + user.encode() + b"\x00"
    body += b"database\x00" + database.encode() + b"\x00"
    body += b"application_name\x00pgaudit\x00"
    body += b"\x00"
    return struct.pack("!I", len(body) + 4) + body

def _password_message(pw):
    body = pw.encode() + b"\x00"
    return b"p" + struct.pack("!I", len(body) + 4) + body

def _md5_auth(user, password, salt):
    inner = hashlib.md5((password + user).encode()).hexdigest()
    outer = hashlib.md5(inner.encode() + salt).hexdigest()
    return "md5" + outer

# ---------------------------------------------------------------------------
# SCRAM-SHA-256 (auth moderne)
# ---------------------------------------------------------------------------
def _scram_client_first(user):
    nonce = base64.b64encode(os.urandom(18)).decode()
    bare = f"n={_saslprep(user)},r={nonce}"
    return nonce, "n,," + bare, bare

def _saslprep(s):
    # SASLprep minimaliste (suffisant pour ASCII usuel)
    return s

def _scram_process(sock, user, password):
    """Effectue le handshake SCRAM-SHA-256. Retourne True si auth OK."""
    nonce, first_full, first_bare = _scram_client_first(user)

    # SASLInitialResponse
    mech = b"SCRAM-SHA-256\x00"
    ir = first_full.encode()
    body = mech + struct.pack("!I", len(ir)) + ir
    sock.sendall(b"p" + struct.pack("!I", len(body) + 4) + body)

    t, payload = _read_message(sock)
    if t != b"R":
        return False, None
    code = struct.unpack("!I", payload[:4])[0]
    if code != 11:  # AuthenticationSASLContinue
        return False, None
    server_first = payload[4:].decode()

    attrs = dict(kv.split("=", 1) for kv in server_first.split(","))
    r = attrs["r"]; s = base64.b64decode(attrs["s"]); i = int(attrs["i"])
    if not r.startswith(nonce):
        return False, None

    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), s, i)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    channel = base64.b64encode(b"n,,").decode()
    final_no_proof = f"c={channel},r={r}"
    auth_msg = f"{first_bare},{server_first},{final_no_proof}"
    client_sig = hmac.new(stored_key, auth_msg.encode(), hashlib.sha256).digest()
    proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
    final = final_no_proof + ",p=" + base64.b64encode(proof).decode()

    fbody = final.encode()
    sock.sendall(b"p" + struct.pack("!I", len(fbody) + 4) + fbody)

    t, payload = _read_message(sock)
    if t != b"R":
        return False, None
    code = struct.unpack("!I", payload[:4])[0]
    # 12 = SASLFinal ; on lit ensuite le AuthenticationOk
    if code == 12:
        t2, payload2 = _read_message(sock)
        if t2 == b"R" and struct.unpack("!I", payload2[:4])[0] == 0:
            return True, None
    return False, None

# ---------------------------------------------------------------------------
# Détection SSL / probe
# ---------------------------------------------------------------------------
def _probe_ssl(host, port, timeout):
    """Teste si le serveur accepte SSLRequest."""
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.sendall(struct.pack("!II", 8, SSL_REQUEST_CODE))
        resp = s.recv(1)
        if resp == b"S":
            s.close()
            return "supported"
        elif resp == b"N":
            s.close()
            return "not_supported"
        s.close()
        return "unknown"
    except Exception:
        return "error"

def _connect(host, port, timeout, use_ssl):
    raw = socket.create_connection((host, port), timeout=timeout)
    raw.settimeout(timeout)
    if use_ssl:
        raw.sendall(struct.pack("!II", 8, SSL_REQUEST_CODE))
        resp = raw.recv(1)
        if resp != b"S":
            raw.close()
            raise ConnectionError("SSL refusé")
        ctx = ssl._create_unverified_context()
        raw = ctx.wrap_socket(raw, server_hostname=host)
    return raw

# ---------------------------------------------------------------------------
# Tentative d'authentification
# ---------------------------------------------------------------------------
def try_login(host, port, user, password, database, timeout, use_ssl):
    """
    Retourne dict:
      status: OK | FAIL | ERROR | AUTH_TRUST | AUTH_UNSUPPORTED
      params: dict des ParameterStatus (version, etc.)
      auth_method: md5|scram|trust|password|...
    """
    result = {"status": "ERROR", "params": {}, "auth_method": None, "err": None}
    try:
        sock = _connect(host, port, timeout, use_ssl)
    except Exception as e:
        result["err"] = f"connect: {e}"
        return result

    try:
        sock.sendall(_startup_packet(user, database))
        while True:
            t, payload = _read_message(sock)
            if t == b"R":  # Authentication
                code = struct.unpack("!I", payload[:4])[0]
                if code == 0:  # AuthenticationOk (trust ou fin)
                    result["auth_method"] = result["auth_method"] or "trust"
                    if result["auth_method"] == "trust":
                        result["status"] = "AUTH_TRUST"
                    else:
                        result["status"] = "OK"
                elif code == 3:  # cleartext
                    result["auth_method"] = "password"
                    sock.sendall(_password_message(password))
                elif code == 5:  # md5
                    result["auth_method"] = "md5"
                    salt = payload[4:8]
                    sock.sendall(_password_message(_md5_auth(user, password, salt)))
                elif code == 10:  # SASL
                    result["auth_method"] = "scram-sha-256"
                    ok, _ = _scram_process(sock, user, password)
                    if ok:
                        result["status"] = "OK"
                    else:
                        result["status"] = "FAIL"
                    # continue pour lire ParameterStatus si OK
                    if result["status"] != "OK":
                        break
                else:
                    result["auth_method"] = f"code_{code}"
                    result["status"] = "AUTH_UNSUPPORTED"
                    break
            elif t == b"S":  # ParameterStatus
                try:
                    parts = payload.split(b"\x00")
                    result["params"][parts[0].decode()] = parts[1].decode()
                except Exception:
                    pass
            elif t == b"K":  # BackendKeyData -> auth réussie
                if result["status"] not in ("OK", "AUTH_TRUST"):
                    result["status"] = "OK"
            elif t == b"Z":  # ReadyForQuery -> session prête
                if result["status"] not in ("AUTH_TRUST",):
                    result["status"] = "OK"
                break
            elif t == b"E":  # ErrorResponse
                fields = _parse_error(payload)
                sev = fields.get("C", "")
                msg = fields.get("M", "")
                if sev == "28P01" or "password" in msg.lower() or "authentication" in msg.lower():
                    result["status"] = "FAIL"
                else:
                    result["status"] = "ERROR"
                    result["err"] = f"{sev}: {msg}"
                break
            else:
                break
    except Exception as e:
        result["err"] = str(e)
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return result

def _parse_error(payload):
    fields = {}
    for chunk in payload.split(b"\x00"):
        if len(chunk) >= 2:
            fields[chr(chunk[0])] = chunk[1:].decode(errors="replace")
        elif len(chunk) == 1:
            fields[chr(chunk[0])] = ""
    return fields

# ---------------------------------------------------------------------------
# Extraction de version
# ---------------------------------------------------------------------------
def _parse_version(params):
    v = params.get("server_version", "")
    m = re.search(r"(\d+)(?:\.(\d+))?", v)
    if not m:
        return None, v
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) else 0
    # PG >= 10 : versioning majeur unique
    numeric = major + (minor / 100.0 if major < 10 else minor / 100.0)
    return numeric, v

def match_cves(numeric):
    if numeric is None:
        return []
    hits = []
    for c in CVE_DB:
        lo, hi = c["range"]
        if lo <= numeric <= hi:
            hits.append(c)
    return hits

# ---------------------------------------------------------------------------
# Audit d'un host
# ---------------------------------------------------------------------------
def audit_host(host, port, timeout):
    report = {
        "host": host, "port": port, "reachable": False, "ssl": None,
        "version": None, "version_raw": None, "auth_method": None,
        "valid_creds": [], "trust_dbs": [], "cves": [], "notes": [],
    }

    ssl_state = _probe_ssl(host, port, timeout)
    report["ssl"] = ssl_state
    use_ssl = (ssl_state == "supported")

    # 1) test trust / récup version via chaque db avec user postgres sans pw
    got_version = False
    for db in DEFAULT_DBS:
        r = try_login(host, port, "postgres", "", db, timeout, use_ssl)
        if r["err"] and "connect" in r["err"]:
            report["notes"].append(r["err"])
            return report
        report["reachable"] = True
        report["auth_method"] = report["auth_method"] or r["auth_method"]
        if r["params"] and not got_version:
            num, raw = _parse_version(r["params"])
            report["version"] = num
            report["version_raw"] = raw
            got_version = True
        if r["status"] == "AUTH_TRUST" or r["status"] == "OK":
            report["trust_dbs"].append(db)
            report["notes"].append(f"AUTH TRUST/OPEN sur db={db} user=postgres (aucun mot de passe requis!)")
        if got_version:
            break

    if not report["reachable"]:
        return report

    # 2) bruteforce léger des creds par défaut
    tested = set()
    for user, pw in DEFAULT_CREDS:
        found_for_user = False
        for db in DEFAULT_DBS:
            key = (user, pw, db)
            if key in tested:
                continue
            tested.add(key)

            r = try_login(host, port, user, pw, db, timeout, use_ssl)

            # récupère la version si pas encore fait
            if r["params"] and report["version"] is None:
                num, raw = _parse_version(r["params"])
                report["version"] = num
                report["version_raw"] = raw
            report["auth_method"] = report["auth_method"] or r["auth_method"]

            if r["status"] in ("OK", "AUTH_TRUST"):
                cred = {
                    "user": user,
                    "password": pw if pw else "<empty>",
                    "database": db,
                    "auth_method": r["auth_method"],
                    "trust": (r["status"] == "AUTH_TRUST"),
                }
                report["valid_creds"].append(cred)
                report["notes"].append(
                    f"CREDS VALIDES: {user}:{pw or '<empty>'} @ db={db} "
                    f"({r['auth_method']})"
                )
                found_for_user = True
                break  # inutile de tester les autres db pour ce couple
            elif r["err"] and "connect" in str(r["err"]):
                report["notes"].append("Connexion perdue pendant le bruteforce")
                return report
        # petite pause anti-flood / éviter fail2ban trop agressif
        if found_for_user:
            continue

    # 3) matching CVE en fonction de la version
    report["cves"] = match_cves(report["version"])

    # 4) enrichissement contextuel des CVE si on a un accès valide
    if report["valid_creds"]:
        has_super_candidate = any(
            c["user"] in ("postgres",) or c["trust"] for c in report["valid_creds"]
        )
        for c in report["cves"]:
            if c["cve"] == "CVE-2019-9193" and has_super_candidate:
                report["notes"].append(
                    "[!] Accès potentiellement superuser -> tester COPY FROM PROGRAM (RCE)"
                )

    return report


# ---------------------------------------------------------------------------
# Parsing des entrées (cibles)
# ---------------------------------------------------------------------------
def parse_hostport(token, default_port=5432):
    """Accepte 'ip', 'ip:port', 'host:port'. Retourne (host, port)."""
    token = token.strip()
    if not token:
        return None
    # IPv6 bracket [::1]:5432
    m = re.match(r"^\[(.+)\]:(\d+)$", token)
    if m:
        return (m.group(1), int(m.group(2)))
    if ":" in token and token.count(":") == 1:
        host, port = token.rsplit(":", 1)
        if port.isdigit():
            return (host, int(port))
    return (token, default_port)


def load_file_targets(path, default_port=5432):
    targets = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            hp = parse_hostport(line, default_port)
            if hp:
                targets.append(hp)
    return targets


def load_nmap_targets(path):
    """
    Supporte:
      - .gnmap (grepable): 'Host: 1.2.3.4 () Ports: 5432/open/tcp//postgresql...'
      - .xml : <address addr=..><port portid=..><state state="open"..>
    Ne retient que les ports PostgreSQL ouverts (service postgresql ou port 5432).
    """
    targets = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        data = f.read()

    if "<nmaprun" in data or data.lstrip().startswith("<?xml"):
        # Parsing XML basique sans dépendance (regex tolérante)
        for host_block in re.findall(r"<host\b.*?</host>", data, re.DOTALL):
            addr_m = re.search(r'<address addr="([^"]+)"[^>]*addrtype="ipv[46]"', host_block)
            if not addr_m:
                addr_m = re.search(r'<address addr="([^"]+)"', host_block)
            if not addr_m:
                continue
            ip = addr_m.group(1)
            for port_block in re.findall(r"<port\b.*?</port>", host_block, re.DOTALL):
                pm = re.search(r'portid="(\d+)"', port_block)
                state_m = re.search(r'<state state="([^"]+)"', port_block)
                svc_m = re.search(r'<service name="([^"]+)"', port_block)
                if not pm or not state_m or state_m.group(1) != "open":
                    continue
                port = int(pm.group(1))
                svc = svc_m.group(1).lower() if svc_m else ""
                if port == 5432 or "postgres" in svc:
                    targets.append((ip, port))
    else:
        # Format grepable (.gnmap)
        for line in data.splitlines():
            if "Host:" not in line or "Ports:" not in line:
                continue
            ipm = re.search(r"Host:\s+([0-9a-fA-F\.:]+)", line)
            if not ipm:
                continue
            ip = ipm.group(1)
            ports_part = line.split("Ports:", 1)[1]
            for entry in ports_part.split(","):
                fields = entry.strip().split("/")
                # format: port/state/proto//service//...
                if len(fields) >= 5:
                    try:
                        port = int(fields[0])
                    except ValueError:
                        continue
                    state = fields[1]
                    service = fields[4].lower()
                    if state == "open" and (port == 5432 or "postgres" in service):
                        targets.append((ip, port))
    # dédup
    return list(dict.fromkeys(targets))


# ---------------------------------------------------------------------------
# Affichage
# ---------------------------------------------------------------------------
class C:
    R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
    M = "\033[95m"; CY = "\033[96m"; W = "\033[97m"; BOLD = "\033[1m"; X = "\033[0m"

def _c(txt, color, use_color):
    return f"{color}{txt}{C.X}" if use_color else txt

def print_report(rep, use_color=True):
    hp = f"{rep['host']}:{rep['port']}"
    if not rep["reachable"]:
        print(_c(f"[-] {hp} injoignable / non PostgreSQL", C.Y, use_color))
        for n in rep["notes"]:
            print(f"      {n}")
        return

    print(_c(f"\n[+] {hp}", C.BOLD + C.CY, use_color))
    print(f"      SSL        : {rep['ssl']}")
    print(f"      Version    : {rep['version_raw'] or 'inconnue'} "
          f"(num={rep['version']})")
    print(f"      Auth       : {rep['auth_method']}")

    if rep["trust_dbs"]:
        print(_c(f"      [!!] TRUST/OPEN sur: {', '.join(rep['trust_dbs'])}",
                 C.R + C.BOLD, use_color))

    if rep["valid_creds"]:
        print(_c("      [!!] CREDENTIALS VALIDES:", C.R + C.BOLD, use_color))
        for c in rep["valid_creds"]:
            tag = " (TRUST)" if c["trust"] else ""
            print(_c(f"          -> {c['user']}:{c['password']} "
                     f"@ {c['database']} [{c['auth_method']}]{tag}",
                     C.R, use_color))
    else:
        print("      Aucun credential par défaut trouvé")

    if rep["cves"]:
        print(_c("      CVE potentielles (selon version):", C.M, use_color))
        for c in rep["cves"]:
            col = C.R if c["sev"] == "CRITICAL" else C.Y
            print(_c(f"          [{c['sev']}] {c['cve']} - {c['title']}",
                     col, use_color))
            print(f"                {c['note']}")
            print(_c(f"                exploit: {c['exploit']}", C.B, use_color))

    for n in rep["notes"]:
        if "TRUST" in n or "CREDS" in n or "[!]" in n:
            continue  # déjà affiché
        print(f"      note: {n}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Audit PostgreSQL sans dépendance (stdlib only)",
        epilog="Usage éthique uniquement — systèmes autorisés."
    )
    ap.add_argument("-i", "--ip", help="IP ou host (accepte host:port)")
    ap.add_argument("-p", "--port", type=int, default=5432, help="Port (def 5432)")
    ap.add_argument("-f", "--file", help="Fichier de cibles (une par ligne, ip ou ip:port)")
    ap.add_argument("--nmap", help="Fichier nmap (.gnmap ou .xml)")
    ap.add_argument("-t", "--timeout", type=float, default=8.0, help="Timeout socket (s)")
    ap.add_argument("-w", "--workers", type=int, default=10, help="Threads parallèles")
    ap.add_argument("-o", "--output", help="Sauvegarde JSON du rapport")
    ap.add_argument("--no-color", action="store_true", help="Désactive les couleurs")
    args = ap.parse_args()

    use_color = not args.no_color and sys.stdout.isatty()

    targets = []
    if args.ip:
        targets.append(parse_hostport(args.ip, args.port))
    if args.file:
        targets += load_file_targets(args.file, args.port)
    if args.nmap:
        targets += load_nmap_targets(args.nmap)

    # dédup en conservant l'ordre
    targets = list(dict.fromkeys(targets))

    if not targets:
        ap.error("Aucune cible. Utilise -i, -f ou --nmap.")

    print(_c(f"[*] pgaudit — {len(targets)} cible(s), "
             f"{args.workers} worker(s)", C.G, use_color))

    reports = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futs = {
            pool.submit(audit_host, h, p, args.timeout): (h, p)
            for (h, p) in targets
        }
        for fut in as_completed(futs):
            h, p = futs[fut]
            try:
                rep = fut.result()
            except Exception as e:
                rep = {"host": h, "port": p, "reachable": False,
                       "notes": [f"exception: {e}"], "ssl": None,
                       "version": None, "version_raw": None,
                       "auth_method": None, "valid_creds": [],
                       "trust_dbs": [], "cves": []}
            reports.append(rep)
            print_report(rep, use_color)

    # Résumé
    vuln = [r for r in reports if r["valid_creds"] or r["trust_dbs"]]
    crit_cve = [r for r in reports
                if any(c["sev"] == "CRITICAL" for c in r["cves"])]
    print(_c(f"\n[*] Résumé: {len(reports)} scannée(s) | "
             f"{len(vuln)} avec creds/trust | "
             f"{len(crit_cve)} avec CVE critique", C.G + C.BOLD, use_color))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2, ensure_ascii=False)
        print(_c(f"[*] Rapport JSON écrit -> {args.output}", C.G, use_color))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrompu.")
        sys.exit(1)
