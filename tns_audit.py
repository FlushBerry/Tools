#!/usr/bin/env python3
"""
tns_audit.py v2 — Auditeur TNS Listener (CVE-2012-1675 / TNS Poisoning)

Corrige les faux positifs : effectue le VRAI test d'enregistrement de service
(comme auxiliary/scanner/oracle/tnspoison_checker) au lieu de se baser sur
la simple réponse du listener.

Usage:
    python3 tns_audit.py -i 10.129.3.77 -p 1576
    python3 tns_audit.py -n scan.xml
    python3 tns_audit.py -f targets.txt

Audit autorisé UNIQUEMENT sur tes propres systèmes / avec autorisation écrite.
"""

import argparse
import socket
import struct
import sys
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

DEFAULT_PORT = 1521
TIMEOUT = 8

# ------------------------------------------------------------------
# Paquets TNS
# ------------------------------------------------------------------

def tns_header(payload: bytes, ptype: int) -> bytes:
    length = len(payload) + 8
    return struct.pack(">HHBBH", length, 0, ptype, 0, 0) + payload


def build_connect(connect_string: bytes) -> bytes:
    """Paquet CONNECT (type 1) portant une chaîne descriptor arbitraire."""
    dlen = len(connect_string)
    # offset standard du CONNECT_DATA
    doffset = 58
    body = struct.pack(
        ">HHHHHHHHHH",
        0x0136,   # version
        0x012C,   # version compatible
        0x0000,   # service options
        0x0800,   # SDU
        0x7FFF,   # TDU
        0x86F0,   # protocol characteristics
        0x0000,   # line turnaround
        0x0001,   # value of 1 in hardware
        dlen,     # length of connect data
        doffset,  # offset to connect data
    )
    body += struct.pack(">IIHHIHHI",
                        0, 0, 0, 0, 0, 0, 0, 0)  # flags / max data etc.
    # padding jusqu'à l'offset
    pad = doffset - (len(body) + 8)
    if pad > 0:
        body += b"\x00" * pad
    body += connect_string
    return tns_header(body, ptype=1)


def recv_tns(sock) -> bytes:
    header = b""
    try:
        while len(header) < 8:
            chunk = sock.recv(8 - len(header))
            if not chunk:
                break
            header += chunk
    except socket.timeout:
        return header
    if len(header) < 8:
        return header
    total = struct.unpack(">H", header[:2])[0]
    body = b""
    remaining = total - 8
    try:
        while remaining > 0:
            chunk = sock.recv(min(4096, remaining))
            if not chunk:
                break
            body += chunk
            remaining -= len(chunk)
    except socket.timeout:
        pass
    return header + body


# ------------------------------------------------------------------
# Résultat
# ------------------------------------------------------------------

@dataclass
class Result:
    host: str
    port: int
    reachable: bool = False
    is_tns: bool = False
    version: str = ""
    vulnerable: bool = None      # True / False / None(indéterminé)
    detail: str = ""


# ------------------------------------------------------------------
# Le VRAI test (aligné sur MSF tnspoison_checker)
# ------------------------------------------------------------------

def audit_target(host: str, port: int) -> Result:
    res = Result(host=host, port=port)

    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            res.reachable = True
            sock.settimeout(TIMEOUT)

            # --- Étape 1 : établir qu'on parle bien à un listener TNS ---
            # On envoie un CONNECT de service registration.
            # C'est la commande d'enregistrement qui déclenche le comportement testé.
            reg_cmd = (
                b"(CONNECT_DATA=(COMMAND=service_register_NSGR))"
            )
            sock.sendall(build_connect(reg_cmd))
            resp = recv_tns(sock)

            if not resp or len(resp) < 5:
                res.detail = "Pas de réponse TNS"
                return res

            ptype = resp[4]
            text = resp.decode("latin-1", errors="ignore")

            # Version (VSNNUM peut être décimal, pas hex)
            m = re.search(r"VSNNUM=(\d+)", text)
            if m:
                vsn = int(m.group(1))
                res.version = f"{(vsn >> 24) & 0xFF}.{(vsn >> 20) & 0xF}"

            # Reconnaissance TNS : type Refuse(4), Accept(2), Resend(11), Marker(12), Data(6)
            if ptype in (2, 4, 6, 11, 12):
                res.is_tns = True
            elif "TNS" in text or "ERROR" in text:
                res.is_tns = True

            if not res.is_tns:
                res.detail = "Ne semble pas être un listener TNS"
                return res

            # --- Étape 2 : ANALYSER LA DÉCISION ---
            # Logique MSF :
            #   - Refuse packet (type 4) contenant un code d'erreur de rejet
            #     d'enregistrement  => NON vulnérable (VNCR actif)
            #   - Accept / pas de refus sur l'enregistrement => vulnérable
            low = text.lower()

            # Codes/messages de REFUS d'enregistrement => protégé
            refuse_signatures = [
                "tns-01189",         # listener could not authenticate
                "tns-12546",         # permission denied
                "tns-01194",
                "not currently known",
                "permission denied",
                "refuse",            # Refuse packet
                "invalid",
            ]

            if ptype == 4:  # Refuse packet
                res.vulnerable = False
                res.detail = "Enregistrement REFUSÉ par le listener (VNCR actif) — non vulnérable"
                return res

            if any(sig in low for sig in refuse_signatures):
                res.vulnerable = False
                res.detail = f"Refus détecté dans la réponse — non vulnérable"
                return res

            # Si le listener ACCEPTE l'enregistrement (Accept packet type 2 / Data)
            # sans refus => vulnérable
            if ptype in (2, 6):
                res.vulnerable = True
                res.detail = "Enregistrement de service ACCEPTÉ sans restriction — VULNÉRABLE (CVE-2012-1675)"
                return res

            # Cas ambigu
            res.vulnerable = None
            res.detail = f"Réponse ambigüe (packet type {ptype}) — confirmer manuellement"

    except socket.timeout:
        res.detail = "Timeout"
    except ConnectionRefusedError:
        res.detail = "Connexion refusée"
    except OSError as e:
        res.detail = f"Erreur réseau: {e}"
    except Exception as e:
        res.detail = f"Erreur: {e}"

    return res


# ------------------------------------------------------------------
# Parsing inputs (inchangé)
# ------------------------------------------------------------------

def parse_nmap_xml(path):
    targets = []
    root = ET.parse(path).getroot()
    for host in root.findall("host"):
        addr = host.find("address")
        if addr is None:
            continue
        ip = addr.get("addr")
        ports = host.find("ports")
        if ports is None:
            continue
        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            pid = int(port.get("portid"))
            name = svc.get("name", "") if svc is not None else ""
            if "oracle" in name.lower() or "tns" in name.lower() or pid == 1521:
                targets.append((ip, pid))
    return targets


def parse_target_file(path):
    targets = []
    rx = re.compile(r"^(?:tns://|oracle://|https?://)?([^:/\s]+)(?::(\d+))?")
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = rx.match(line)
            if m:
                targets.append((m.group(1),
                                int(m.group(2)) if m.group(2) else DEFAULT_PORT))
    return targets


# ------------------------------------------------------------------
# Affichage
# ------------------------------------------------------------------

C = {"red": "\033[91m", "green": "\033[92m", "yellow": "\033[93m",
     "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m"}
def col(t, c): return f"{C[c]}{t}{C['reset']}"

def show(r: Result):
    tgt = f"{r.host}:{r.port}"
    if not r.reachable:
        print(f"[{col('----', 'yellow')}] {tgt:<22} injoignable ({r.detail})"); return
    if not r.is_tns:
        print(f"[{col('----', 'yellow')}] {tgt:<22} non-TNS ({r.detail})"); return
    if r.vulnerable is True:
        tag = col("VULN", "red")
    elif r.vulnerable is False:
        tag = col(" OK ", "green")
    else:
        tag = col(" ?? ", "yellow")
    ver = f" v{r.version}" if r.version else ""
    print(f"[{tag}] {tgt:<22}{ver}  {r.detail}")


def main():
    p = argparse.ArgumentParser(description="Audit TNS Listener v2 — vrai test CVE-2012-1675")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("-i", "--ip")
    p.add_argument("-p", "--port", type=int, default=DEFAULT_PORT)
    g.add_argument("-n", "--nmap")
    g.add_argument("-f", "--file")
    p.add_argument("-t", "--threads", type=int, default=10)
    a = p.parse_args()

    if a.ip:
        targets = [(a.ip, a.port)]
    elif a.nmap:
        targets = parse_nmap_xml(a.nmap)
    else:
        targets = parse_target_file(a.file)

    targets = list(dict.fromkeys(targets))
    if not targets:
        print(col("Aucune cible.", "red")); sys.exit(1)

    print(col(f"\n=== Audit TNS Listener v2 — {len(targets)} cible(s) ===\n", "bold"))
    print(col(" ! Autorisé uniquement sur tes propres systèmes.\n", "cyan"))

    results = []
    with ThreadPoolExecutor(max_workers=a.threads) as ex:
        futs = {ex.submit(audit_target, h, pt): (h, pt) for h, pt in targets}
        for f in as_completed(futs):
            r = f.result(); results.append(r); show(r)

    vuln = [r for r in results if r.vulnerable is True]
    amb  = [r for r in results if r.vulnerable is None and r.is_tns]
    print(col(f"\n=== {len(vuln)} vulnérable(s), {len(amb)} à confirmer, "
              f"{len(results)} total ===", "bold"))


if __name__ == "__main__":
    main()
