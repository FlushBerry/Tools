#!/usr/bin/env python3
"""
mongo_audit.py — audit MongoDB sans dépendances externes
Usage: python3 mongo_audit.py <host> [port]
"""
import socket, struct, os, sys, base64, hmac, hashlib, time

# =============== BSON ===============
def e_cstring(s): return s.encode() + b"\x00"
def e_int32(n,v): return b"\x10"+e_cstring(n)+struct.pack("<i",v)
def e_int64(n,v): return b"\x12"+e_cstring(n)+struct.pack("<q",v)
def e_string(n,v):
    d=v.encode()+b"\x00"
    return b"\x02"+e_cstring(n)+struct.pack("<i",len(d))+d
def e_bool(n,v): return b"\x08"+e_cstring(n)+(b"\x01" if v else b"\x00")
def e_binary(n,d,st=0):
    return b"\x05"+e_cstring(n)+struct.pack("<i",len(d))+bytes([st])+d
def e_doc(n,doc): return b"\x03"+e_cstring(n)+doc
def bson_doc(fields):
    body=b"".join(fields); total=4+len(body)+1
    return struct.pack("<i",total)+body+b"\x00"

def parse_bson(data, off=0):
    size=struct.unpack_from("<i",data,off)[0]; end=off+size; off+=4
    out={}
    while off < end-1:
        t=data[off]; off+=1
        if t == 0: break
        z=data.index(b"\x00",off)
        name=data[off:z].decode("utf-8","replace"); off=z+1
        try:
            if   t==0x01: val=struct.unpack_from("<d",data,off)[0]; off+=8
            elif t==0x02:
                l=struct.unpack_from("<i",data,off)[0]; off+=4
                val=data[off:off+l-1].decode("utf-8","replace"); off+=l
            elif t==0x03:
                sz=struct.unpack_from("<i",data,off)[0]
                val,_=parse_bson(data,off); off+=sz
            elif t==0x04:
                sz=struct.unpack_from("<i",data,off)[0]
                d,_=parse_bson(data,off); off+=sz
                val=[d[k] for k in sorted(d.keys(), key=lambda x:int(x) if x.isdigit() else 0)]
            elif t==0x05:
                l=struct.unpack_from("<i",data,off)[0]; off+=4
                off+=1  # subtype
                val=data[off:off+l]; off+=l
            elif t==0x07: val=data[off:off+12].hex(); off+=12
            elif t==0x08: val=bool(data[off]); off+=1
            elif t==0x09: val=struct.unpack_from("<q",data,off)[0]; off+=8
            elif t==0x0A: val=None
            elif t==0x10: val=struct.unpack_from("<i",data,off)[0]; off+=4
            elif t==0x11: val=struct.unpack_from("<q",data,off)[0]; off+=8
            elif t==0x12: val=struct.unpack_from("<q",data,off)[0]; off+=8
            else:
                out[name]=f"<unsupported 0x{t:02x}>"
                return out,end
            out[name]=val
        except Exception as e:
            out[name]=f"<parse error: {e}>"
            return out,end
    return out,end

# =============== Wire protocol ===============
REQ_ID = 0
def op_msg(doc):
    global REQ_ID; REQ_ID += 1
    section=b"\x00"+doc
    body=struct.pack("<I",0)+section
    length=16+len(body)
    return struct.pack("<iiii", length, REQ_ID, 0, 2013) + body

def send_cmd(sock, doc, timeout=5):
    sock.settimeout(timeout)
    sock.sendall(op_msg(doc))
    hdr=b""
    while len(hdr) < 16:
        chunk = sock.recv(16-len(hdr))
        if not chunk: raise ConnectionError("closed")
        hdr += chunk
    msg_len = struct.unpack("<i", hdr[:4])[0]
    rest=b""
    while len(rest) < msg_len-16:
        chunk = sock.recv(msg_len-16-len(rest))
        if not chunk: raise ConnectionError("closed mid-msg")
        rest += chunk
    # skip flags(4) + section kind(1)
    r,_ = parse_bson(rest[5:])
    return r

def connect(host, port):
    return socket.create_connection((host, port), timeout=5)

def cmd(sock, name, db="admin", extra=None):
    fields = [e_int32(name, 1)]
    if extra:
        for f in extra: fields.append(f)
    fields.append(e_string("$db", db))
    return send_cmd(sock, bson_doc(fields))

def is_ok(r):
    v = r.get("ok")
    return v == 1 or v == 1.0

def short(r, n=200):
    s = str(r)
    return s if len(s) <= n else s[:n] + "...[truncated]"

# =============== SCRAM ===============
def hi(pwd, salt, iters, hashfn):
    return hashlib.pbkdf2_hmac(hashfn, pwd, salt, iters, hashlib.new(hashfn).digest_size)

def scram_auth(sock, user, password, db, mechanism="SCRAM-SHA-256"):
    hashfn = "sha256" if mechanism == "SCRAM-SHA-256" else "sha1"
    # MongoDB exige hash MD5 du pass pour SCRAM-SHA-1
    if mechanism == "SCRAM-SHA-1":
        pwd_bytes = hashlib.md5(f"{user}:mongo:{password}".encode()).hexdigest().encode()
    else:
        pwd_bytes = password.encode()

    nonce = base64.b64encode(os.urandom(24)).decode()
    user_esc = user.replace("=","=3D").replace(",","=2C")
    first_bare = f"n={user_esc},r={nonce}"
    client_first = f"n,,{first_bare}"

    r = send_cmd(sock, bson_doc([
        e_int32("saslStart",1),
        e_string("mechanism", mechanism),
        e_binary("payload", client_first.encode()),
        e_int32("autoAuthorize",1),
        e_string("$db", db),
    ]))
    if not is_ok(r):
        return False, r.get("errmsg","saslStart failed")

    conv_id = r["conversationId"]
    server_first = r["payload"].decode() if isinstance(r["payload"], bytes) else r["payload"]
    fields = dict(p.split("=",1) for p in server_first.split(","))
    r_nonce, salt_b64, iters = fields["r"], fields["s"], int(fields["i"])
    if not r_nonce.startswith(nonce):
        return False, "bad server nonce"
    salt = base64.b64decode(salt_b64)

    salted = hi(pwd_bytes, salt, iters, hashfn)
    client_key = hmac.new(salted, b"Client Key", hashfn).digest()
    stored_key = hashlib.new(hashfn, client_key).digest()
    cb = base64.b64encode(b"n,,").decode()
    cf_no_proof = f"c={cb},r={r_nonce}"
    auth_msg = f"{first_bare},{server_first},{cf_no_proof}"
    client_sig = hmac.new(stored_key, auth_msg.encode(), hashfn).digest()
    proof = bytes(a^b for a,b in zip(client_key, client_sig))
    client_final = f"{cf_no_proof},p={base64.b64encode(proof).decode()}"

    r = send_cmd(sock, bson_doc([
        e_int32("saslContinue",1),
        e_int32("conversationId", conv_id),
        e_binary("payload", client_final.encode()),
        e_string("$db", db),
    ]))
    if not is_ok(r):
        return False, r.get("errmsg","auth rejected")

    # Possible 3rd round (server verifier) — on accepte si done=True ou on envoie un saslContinue vide
    if not r.get("done", False):
        r = send_cmd(sock, bson_doc([
            e_int32("saslContinue",1),
            e_int32("conversationId", conv_id),
            e_binary("payload", b""),
            e_string("$db", db),
        ]))
        if not is_ok(r):
            return False, r.get("errmsg","final step failed")
    return True, "AUTH OK"

# =============== Phases ===============
def banner(t):
    print(f"\n\033[1;36m=== {t} ===\033[0m")

def phase_fingerprint(host, port):
    banner("1. FINGERPRINT")
    s = connect(host, port)
    r = cmd(s, "hello")
    print(f"  isWritablePrimary : {r.get('isWritablePrimary')}")
    print(f"  maxWireVersion    : {r.get('maxWireVersion')}")
    print(f"  readOnly          : {r.get('readOnly')}")
    print(f"  msg               : {r.get('msg')}")
    print(f"  setName (replica) : {r.get('setName')}")
    r = cmd(s, "buildInfo")
    print(f"  version           : {r.get('version')}")
    print(f"  gitVersion        : {r.get('gitVersion')}")
    print(f"  openssl           : {r.get('openssl')}")
    print(f"  storageEngines    : {r.get('storageEngines')}")
    s.close()

def phase_preauth_enum(host, port):
    banner("2. ENUM PRE-AUTH (commandes accessibles sans login)")
    cmds = [
        "ping", "whatsmyuri", "listCommands", "isdbgrid",
        "getFreeMonitoringStatus", "replSetGetStatus", "getLog",
        "hostInfo", "serverStatus", "getParameter", "getCmdLineOpts",
        "connPoolStats", "top", "dbStats", "listDatabases",
        "currentOp", "features", "connectionStatus",
    ]
    accessible, denied, errors = [], [], []
    for c in cmds:
        try:
            s = connect(host, port)
            extra = [e_string("getLog","global")] if c == "getLog" else None
            # listCommands a une syntaxe particulière (pas de "1" en valeur)
            r = cmd(s, c, extra=extra)
            s.close()
            if is_ok(r):
                accessible.append((c, r))
            else:
                err = (r.get("errmsg") or "").lower()
                if "auth" in err or "unauthorized" in err or r.get("code") == 13:
                    denied.append(c)
                else:
                    errors.append((c, r.get("errmsg","?"), r.get("code")))
        except Exception as e:
            errors.append((c, str(e), None))

    print(f"\n  \033[1;32m[+] Accessibles SANS auth ({len(accessible)}):\033[0m")
    for c, r in accessible:
        print(f"    \033[32m✓\033[0m {c}")
        # extraits intéressants
        if c == "whatsmyuri":
            print(f"        you = {r.get('you')}")
        elif c == "connectionStatus":
            ai = r.get("authInfo", {})
            print(f"        authenticatedUsers     = {ai.get('authenticatedUsers')}")
            print(f"        authenticatedUserRoles = {ai.get('authenticatedUserRoles')}")
        elif c == "listCommands":
            cmds_dict = r.get("commands", {})
            if isinstance(cmds_dict, dict):
                print(f"        total commands exposed = {len(cmds_dict)}")
        elif c == "getFreeMonitoringStatus":
            print(f"        state = {r.get('state')} url = {r.get('url')}")
        elif c == "buildInfo":
            pass
        else:
            print(f"        {short(r, 180)}")

    print(f"\n  \033[1;33m[~] Refusés (auth requise) ({len(denied)}):\033[0m")
    print(f"    {', '.join(denied)}")
    if errors:
        print(f"\n  \033[1;31m[!] Erreurs/autres ({len(errors)}):\033[0m")
        for c, e, code in errors:
            print(f"    {c}: code={code} msg={e[:100]}")

def phase_default_creds(host, port):
    banner("3. TEST CREDENTIALS PAR DÉFAUT (SCRAM)")
    # Liste minimaliste et prudente (bug bounty friendly)
    pairs = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "mongo"),
        ("admin", "mongodb"),
        ("admin", "admin123"),
        ("admin", "changeme"),
        ("admin", ""),
        ("root", "root"),
        ("root", "toor"),
        ("root", "password"),
        ("root", "mongo"),
        ("mongo", "mongo"),
        ("mongoadmin", "mongoadmin"),
        ("mongodb", "mongodb"),
        ("user", "user"),
        ("test", "test"),
        ("backup", "backup"),
        ("guest", "guest"),
    ]
    dbs = ["admin"]
    mechanisms = ["SCRAM-SHA-256", "SCRAM-SHA-1"]
    found = []

    total = len(pairs) * len(dbs) * len(mechanisms)
    print(f"  {total} tentatives à tester (lentement, 0.3s entre chaque)...\n")

    for db in dbs:
        for mech in mechanisms:
            for u, p in pairs:
                try:
                    s = connect(host, port)
                    ok, msg = scram_auth(s, u, p, db, mech)
                    s.close()
                    tag = f"[{mech}] {db}/{u}:{p!r}"
                    if ok:
                        print(f"  \033[1;32m[+++] SUCCESS {tag}\033[0m")
                        found.append((u, p, db, mech))
                    else:
                        # n'affiche pas les "Authentication failed" pour rester lisible
                        if "fail" not in msg.lower() and "not found" not in msg.lower() and "match" not in msg.lower():
                            print(f"  [?] {tag} → {msg[:80]}")
                except Exception as e:
                    print(f"  [!] err {u}:{p}: {e}")
                time.sleep(0.3)

    if not found:
        print("\n  \033[1;33m[-] Aucun credential par défaut trouvé.\033[0m")
    return found

def phase_postauth(host, port, creds):
    banner("4. POST-AUTH DUMP")
    u, p, db, mech = creds[0]
    s = connect(host, port)
    ok, _ = scram_auth(s, u, p, db, mech)
    if not ok:
        print("  re-auth failed"); return

    print(f"  authentifié comme {u}@{db}")
    r = cmd(s, "listDatabases")
    print("\n  Databases:")
    for d in r.get("databases", []):
        print(f"    - {d.get('name')} ({d.get('sizeOnDisk')} bytes)")

    # users
    r = cmd(s, "usersInfo", extra=[e_int32("usersInfo",1)])
    # plus propre :
    r = send_cmd(s, bson_doc([
        e_doc("usersInfo", bson_doc([e_int32("forAllDBs",1)])),
        e_string("$db","admin"),
    ]))
    if is_ok(r):
        print("\n  Users:")
        for u in r.get("users", []):
            print(f"    - {u.get('user')}@{u.get('db')}  roles={u.get('roles')}")
    s.close()

# =============== Main ===============
def main():
    if len(sys.argv) < 2:
        print("Usage: python3 mongo_audit.py <host> [port]")
        sys.exit(1)
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 27017

    print(f"\033[1mTarget: {host}:{port}\033[0m")
    try:
        phase_fingerprint(host, port)
        phase_preauth_enum(host, port)
        found = phase_default_creds(host, port)
        if found:
            phase_postauth(host, port, found)
    except KeyboardInterrupt:
        print("\n[!] interrompu")
    except Exception as e:
        print(f"\n[!] erreur globale: {e}")

if __name__ == "__main__":
    main()
