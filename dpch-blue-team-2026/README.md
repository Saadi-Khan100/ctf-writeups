# DPCH Online Qualifiers 2026 - Blue Team

Five blue team challenges solved during the DPCH Online Qualifiers, played on the Cydea Range
platform. Each writeup walks through every command that was run, why it was run, what came back,
and how one step led to the next until the flag appeared. The failed attempts are kept in,
because the mistakes are the part worth reading.

Listed in the order they were solved.

| Challenge | Category | Writeup |
| --- | --- | --- |
| Breachmaster | Credential Access | [breachmaster.md](breachmaster.md) |
| Plainwire | Intrusion Reconstruction | [plainwire.md](plainwire.md) |
| RedBulb | Network Forensics | [redbulb.md](redbulb.md) |
| Apartment | Incident Response | [apartment.md](apartment.md) |
| Antiobook | Malware Analysis | [antiobook.md](antiobook.md) |

[What I learned](lessons-learned.md) collects the mistakes that actually cost time across all five.

## Scripts

| File | What it does |
| --- | --- |
| [`scripts/antino_cfg_decode.py`](scripts/antino_cfg_decode.py) | Recovers the Antino implant config from a memory dump or binary, walking non-zero runs and testing both phases of the alternating 0xAB/0xCD XOR |
| [`scripts/antino_stage2_decrypt.py`](scripts/antino_stage2_decrypt.py) | Decrypts Antino stage-2 resources, reading the loader for its custom base64 alphabet and RC4 key so it works across campaigns |

Run them against the evidence from your own instance.

```bash
python3 scripts/antino_cfg_decode.py memdump_GatherOsState_pid4821_*.bin
python3 scripts/antino_stage2_decrypt.py Qw7Womin4X6N HzjNPgRE9ir92e38.txt
```

## Note on the decoys

Every challenge in this set had planted distractions, and they were good ones.

- RedBulb: 3,431 extracted HTTP objects, dozens of fake `MZ` headers, and a `.pdf.exe` double
  extension download served from an address range reserved for documentation.
- Apartment: two different files both named `TenantUpdate.exe`, with different hashes, written by
  two different processes.
- Antiobook: three hosts and three separate campaigns, only one of them the researcher in the brief.
- Plainwire: ten clear text credential pairs in one dump, and only one of them reused.
- Breachmaster: four accounts in the dump, three of them service accounts.

## Note on the flags

The flags printed in these writeups are per-team and tied to instances that no longer exist, so
they are kept only to show what the platform actually accepted.
