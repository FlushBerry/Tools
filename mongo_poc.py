#!/usr/bin/env python3
import socket, struct, sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT   = int(sys.argv[2]) if len(sys.argv) > 2 else 27017

# ---------- Encodeur BSON minimal ----------
def e_cstring(s): return s.encode() + b"\x00"

def e_int32(name, v):
    return b"\x10" + e_cstring(name) + struct.pack("<i", v)

def e_string(name, v):
    data = v.encode() + b"\x00"
    return b"\x02" + e_cstring(name) + struct.pack("<i", len(data)) + data

def e_doc(name, doc):
    return b"\x03" + e_cstring(name) + doc

def bson_doc(fields):
    body = b"".join(fields)
    total = 4 + len(body) + 1
    return struct.pack("<i", total) + body + b"\x00"

# ---------- Décodeur BSON très permissif ----------
def parse_bson(data, off=0):
    size = struct.unpack_from("<i", data, off)[0]
    end  = off + size
    off += 4
    out = {}
    while off < end - 1:
        t = data[off]; off += 1
        # cstring name
        z = data.index(b"\x00", off)
        name = data[off:z].decode("utf-8", "replace")
        off = z + 1
        if t == 0x01:   # double
            val = struct.unpack_from("<d", data, off)[0]; off += 8
        elif t == 0x02: # string
            l = struct.unpack_from("<i", data, off)[0]; off += 4
            val = data[off:off+l-1].decode("utf-8","replace"); off += l
        elif t == 0x03 or t == 0x04: # doc / array
            sz = struct.unpack_from("<i", data, off)[0]
            val, _ = parse_bson(data, off); off += sz
        elif t == 0x08: # bool
            val = bool(data[off]); off += 1
        elif t == 0x10: # int32
            val = struct.unpack_from("<i", data, off)[0]; off += 4
        elif t == 0x12: # int64
            val = struct.unpack_from("<q", data, off)[0]; off += 8
        elif t == 0x0A: # null
            val = None
        else:
            val = f"<type 0x{t:02x}>"
            # tentative de skip; on coupe ici
            return out, end
        out[name] = val
    return out, end

# ---------- OP_MSG ----------
def op_msg(command_doc):
    # OP_MSG = header(16) + flags(4) + section(kind=0 + bson)
    section = b"\x00" + command_doc
    body    = struct.pack("<I", 0) + section
    opcode  = 2013  # OP_MSG
    req_id  = 1
    length  = 16 + len(body)
    header  = struct.pack("<iiii", length, req_id, 0, opcode)
    return header + body

def send_cmd(sock, doc):
    sock.sendall(op_msg(doc))
    # read header
    hdr = b""
    while len(hdr) < 16:
        hdr += sock.recv(16 - len(hdr))
    msg_len = struct.unpack("<i", hdr[:4])[0]
    rest = b""
    while len(rest) < msg_len - 16:
        rest += sock.recv(msg_len - 16 - len(rest))
    # rest = flags(4) + sections
    flags = rest[:4]
    section_kind = rest[4]
    bson_blob = rest[5:]
    parsed, _ = parse_bson(bson_blob)
    return parsed

# ---------- Tests ----------
def main():
    print(f"[*] Connexion {TARGET}:{PORT}")
    s = socket.create_connection((TARGET, PORT), timeout=5)

    # 1. hello / isMaster (no auth required)
    print("\n[+] === hello ===")
    cmd = bson_doc([
        e_int32("hello", 1),
        e_string("$db", "admin"),
    ])
    r = send_cmd(s, cmd)
    for k,v in r.items(): print(f"  {k} = {v}")

    # 2. buildInfo
    print("\n[+] === buildInfo ===")
    cmd = bson_doc([
        e_int32("buildInfo", 1),
        e_string("$db", "admin"),
    ])
    r = send_cmd(s, cmd)
    print(f"  version = {r.get('version')}")
    print(f"  gitVersion = {r.get('gitVersion')}")

    # 3. listDatabases  (★ test d'auth)
    print("\n[+] === listDatabases (test accès non authentifié) ===")
    cmd = bson_doc([
        e_int32("listDatabases", 1),
        e_string("$db", "admin"),
    ])
    r = send_cmd(s, cmd)
    if r.get("ok") == 1.0 or r.get("ok") == 1:
        print("  [!!!] ACCÈS NON AUTHENTIFIÉ — VULNÉRABLE")
        print(f"  databases (raw): {r.get('databases')}")
    else:
        print(f"  ok={r.get('ok')} errmsg={r.get('errmsg')} code={r.get('code')}")

    # 4. connectionStatus → révèle privilèges courants
    print("\n[+] === connectionStatus ===")
    cmd = bson_doc([
        e_int32("connectionStatus", 1),
        e_string("$db", "admin"),
    ])
    r = send_cmd(s, cmd)
    print(f"  {r}")

    # 5. getCmdLineOpts → révèle config (auth activée ou pas)
    print("\n[+] === getCmdLineOpts ===")
    cmd = bson_doc([
        e_int32("getCmdLineOpts", 1),
        e_string("$db", "admin"),
    ])
    r = send_cmd(s, cmd)
    print(f"  ok={r.get('ok')} errmsg={r.get('errmsg')}")
    if r.get("ok") == 1 or r.get("ok") == 1.0:
        print("  [!!!] LECTURE CONFIG SERVEUR SANS AUTH")
        print(f"  parsed = {r.get('parsed')}")

    s.close()

if __name__ == "__main__":
    main()
