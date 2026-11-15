#!/usr/bin/env python3
"""Decrypt Antino stage-2 resources: custom-alphabet base64, then RC4.

The stage-2 loader ships both halves of its own crypto:

    var _alphabet = "qYPwzs07b9MUeLZcrHEhyWGt/OX35IaSAxJp2Qv6Rjf1oNuB+4FdClD8KinVTkgm";
    var _k64      = "LD/d/h24/dHJZ0y+LGrFLA==";

The catch is that _k64 must also be decoded with the CUSTOM alphabet, not the
standard base64 table. It decodes cleanly under the standard table and yields a
wrong 16 byte RC4 key with no error, which is the easiest way to lose an hour.

Usage:
    python3 antino_stage2_decrypt.py <loader_file> <encrypted_file> [<encrypted_file> ...]

The loader is parsed for _alphabet and _k64, so this also works on other
campaigns that ship a different alphabet or key.
"""
import re
import sys

STD = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def b64_custom(text, alphabet):
    """Base64 decode using an arbitrary 64 character alphabet."""
    text = "".join(text.split())
    out = bytearray()
    for i in range(0, len(text), 4):
        group = []
        for j in range(4):
            ch = text[i + j] if i + j < len(text) else '='
            group.append(0 if ch == '=' else alphabet.find(ch))
        packed = (group[0] << 18) | (group[1] << 12) | (group[2] << 6) | group[3]
        out.append((packed >> 16) & 0xFF)
        if i + 2 < len(text) and text[i + 2] != '=':
            out.append((packed >> 8) & 0xFF)
        if i + 3 < len(text) and text[i + 3] != '=':
            out.append(packed & 0xFF)
    return bytes(out)


def rc4(key, data):
    S = list(range(256))
    j = 0
    for i in range(256):                      # key scheduling
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for byte in data:                         # keystream generation
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)

    loader = open(sys.argv[1]).read()

    m_alpha = re.search(r'_alphabet\s*=\s*"([^"]+)"', loader)
    m_key = re.search(r'_k64\s*=\s*"([^"]+)"', loader)
    if not (m_alpha and m_key):
        sys.exit("could not find _alphabet and _k64 in the loader")

    alphabet = m_alpha.group(1)
    key = b64_custom(m_key.group(1), alphabet)

    print(f"alphabet : {alphabet}")
    print(f"RC4 key  : {key!r}")
    if len(alphabet) != 64:
        print(f"warning  : alphabet is {len(alphabet)} characters, expected 64")

    for path in sys.argv[2:]:
        plain = rc4(key, b64_custom(open(path).read(), alphabet))
        print(f"\n########## {path} -> {len(plain)} bytes ##########")
        print(plain.decode('utf8', 'replace'))


if __name__ == '__main__':
    main()
