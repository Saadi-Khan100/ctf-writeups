#!/usr/bin/env python3
"""Recover the Antino implant configuration from a memory dump or binary.

The config is stored with an alternating XOR of 0xAB and 0xCD. Two things make
this awkward by hand:

  * the offset is not fixed, so the script walks every run of non-zero bytes
    instead of expecting the blob in one place
  * the alternation has two possible phases, because the blob may begin on the
    0xAB byte or on the 0xCD byte. Getting it backwards produces garbage that
    looks exactly like a wrong key, so both are tried.

Usage:
    python3 antino_cfg_decode.py <file> [<file> ...]
"""
import sys

KEYS = (0xAB, 0xCD)
MIN_RUN = 48
PRINTABLE_RATIO = 0.90


def nonzero_runs(data, minimum=MIN_RUN):
    """Yield (start, end) for every run of non-zero bytes of useful length."""
    i = 0
    while i < len(data):
        if data[i]:
            j = i
            while j < len(data) and data[j]:
                j += 1
            if j - i >= minimum:
                yield i, j
            i = j
        else:
            i += 1


def looks_like_text(blob):
    good = sum(32 <= c < 127 or c in (9, 10, 13) for c in blob)
    return good > len(blob) * PRINTABLE_RATIO


def decode(blob, phase):
    return bytes(b ^ KEYS[(n + phase) % 2] for n, b in enumerate(blob))


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)

    for path in sys.argv[1:]:
        with open(path, 'rb') as fh:
            data = fh.read()

        print(f"########## {path} ({len(data)} bytes) ##########")
        for start, end in nonzero_runs(data):
            for phase in (0, 1):
                out = decode(data[start:end], phase)
                if looks_like_text(out):
                    print(f"--- offset {hex(start)} len {end - start} phase {phase} ---")
                    print(out.decode('utf8', 'replace'))


if __name__ == '__main__':
    main()
