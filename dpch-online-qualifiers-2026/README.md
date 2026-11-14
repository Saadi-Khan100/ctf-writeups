# DPCH Online Qualifiers 2026

Four challenges solved during the DPCH Online Qualifiers, played on the Cydea Range platform.
Each writeup walks through every command that was run, why it was run, what came back, and how
one step led to the next until the flag appeared. The failed attempts are kept in, because the
mistakes are the part worth reading.

| Challenge | Category | Writeup |
| --- | --- | --- |
| Waybill | Web | [waybill.md](waybill.md) |
| Helios Vault | Programming | [helios-vault.md](helios-vault.md) |
| Promise | Crypto | [promise.md](promise.md) |
| Meeeps | Pwn | [meeeps.md](meeeps.md) |

[What I learned](lessons-learned.md) collects the mistakes that actually cost time across all four.

## Scripts

| File | What it does |
| --- | --- |
| [`scripts/get_promise.py`](scripts/get_promise.py) | Dumps the Promise public key and ciphertext to a file before the instance expires |
| [`scripts/promise_solver.py`](scripts/promise_solver.py) | Full offline key recovery and decryption for Promise (Lagrange-Gauss lattice reduction) |
| [`scripts/helios.py`](scripts/helios.py) | Shamir secret-sharing solver for Helios Vault, 50 rounds over newline-delimited JSON |
| [`scripts/meeeps_exploit.py`](scripts/meeeps_exploit.py) | MIPS32 GOT overwrite for Meeeps: leak, locate the stack frame, swap `puts` for `system` |

Run them against your own instance, with the host and port from the challenge page.

```bash
python3 scripts/get_promise.py
python3 scripts/promise_solver.py promise_out.txt
python3 scripts/meeeps_exploit.py <host> <port>
```

## Note on the flags

The flags printed in these writeups are per-team and tied to an instance that no longer exists,
so they are kept only to show what the services actually returned.
