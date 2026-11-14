# Helios Vault

## Understanding the challenge

|  |  |
| --- | --- |
| Category | Programming |
| Event | DPCH Online Qualifiers (Cydea Range platform) |
| Target | `nc 52.146.88.61 35719` - raw TCP (earlier instances: 35292, 35418) |
| Files given | none - the service itself is the whole challenge |

### What the challenge says

The Helios key-management vault keeps a master secret split into shares. An "unseal" service hands you a quorum of those shares and asks you to hand back the reconstructed secret. It does this **fifty times in a twenty-second window**.

That time limit is the real statement of the problem. Fifty rounds in twenty seconds is 0.4 seconds per round. Nobody is doing this by hand. The challenge is not "can you solve one", it is "can you write a program that solves it before the clock runs out".

The same instance warning applies here. The port changed from `35292` to `35418` to `35719` across this solve, because each container expired. If the connection is refused, open a fresh instance and use the new port.

### Reading the protocol before writing any code

```bash
nc 52.146.88.61 35418
```

`nc` (netcat) opens a plain TCP connection and prints whatever the server sends. Before writing a solver I need to see the exact wording of the messages - what fields exist, what they are called, and what shape of answer the server wants. Guessing this and then debugging a script is much slower than looking once.

The first two lines that arrived:

```json
{"service": "Helios Vault :: threshold unseal", "format": "newline-delimited JSON - one request per line, answer with one line", "rounds": 50, "window_seconds": 20.0}
{"round": 1, "prime": 1415591023304249221, "threshold": 7, "shares": [[757843186666719810, 6577346786954490], ...]}
```

Three important things are now known:

- The protocol is **newline-delimited JSON**. One JSON object per line, in both directions. No length prefixes, no framing to work out.
- Each round gives a fresh `prime`, a `threshold`, and a list of `shares`, where every share is a pair `[x, y]`.
- The field holding the modulus is named `prime`. Not `mod`, not `modulus`. That detail cost me an attempt later.

### What the maths is

This is Shamir's Secret Sharing. The vault picked a random polynomial over the finite field `GF(p)`:

```text
f(x) = secret + a1*x + a2*x^2 + ... + a_{t-1}*x^(t-1)   (mod p)
```

The secret is hidden in the constant term, which is just `f(0)`. Each share is a point `(x, f(x))` on that curve.

A polynomial of degree `t-1` is pinned down completely by `t` points. The server gives me exactly `t` points. So there is only one possible polynomial, and the only thing left to do is evaluate it at zero.

**Lagrange interpolation** does that in one formula, without ever building the polynomial:

```text
secret = sum over i of:  y_i * (product over j != i of  (-x_j) * (x_i - x_j)^-1)   (mod p)
```

In words: for each share, work out a weight that is 1 at that share's own `x` and 0 at every other share's `x`, multiply by that share's `y`, and add them all up. Evaluated at `x = 0`, those weights are `(-x_j) / (x_i - x_j)`.

The only tricky step is the division. In a finite field you cannot just divide; you multiply by the **modular inverse**. Python gives that for free since 3.8:

```python
pow(den, -1, prime)   # the number that satisfies den * result == 1 (mod prime)
```

That single builtin is why this challenge is short in Python and painful in C.

## The failed attempt, the fix, and the flag

I did not get this right the first time. Both mistakes are kept below, because both of them cost real minutes in a timed event.

### Attempt 1: the generic parser that did not read the protocol

The first script did not parse the server's JSON. It used regular expressions to pull numbers out of whatever text arrived - find the shares, find the modulus, interpolate, send the answer back. The idea was that a generic parser would work against any share-based service.

It did not work. Two separate things went wrong.

**Mistake 1 - it looked for the wrong field name.** The regex searched for a word like `mod` or `modulus` to find the prime. But the server calls the field `prime`. The regex found nothing, so the modulus defaulted to something useless and the arithmetic was never reduced properly. The result:

```text
[Reconstructed secret: 11339467921629076547306]
```

That number is **larger than the prime itself** (`1415591023304249221`). In a finite field every value must be smaller than the modulus. Seeing a result bigger than `p` is an instant tell that the modulus was never applied. Always sanity-check that the answer is in range before sending it.

**Mistake 2 - it sent the answer in the wrong shape.** The script replied with a bare integer on the line. The server wants a JSON object. It said so clearly:

```text
{"status": "error", "round": 1, "detail": "malformed answer; expected {"secret": <int>}"}
```

That is a good error message and it names the exact fix. Both mistakes have the same root: the banner told me the format in the very first line, and the first script ignored it. **Read the protocol, then write to that protocol.** A generic parser is slower than a specific one.

### Attempt 2: the working solver

The fix was to stop guessing and parse the JSON properly.

```python
import socket, json

def lagrange_at_zero(points, prime):
    secret = 0
    for i, (xi, yi) in enumerate(points):
        num = den = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * (-xj)) % prime
            den = (den * (xi - xj)) % prime
        secret = (secret + yi * num * pow(den, -1, prime)) % prime
    return secret

s = socket.create_connection(("52.146.88.61", 35719))
f = s.makefile("rwb")

for line in f:
    msg = json.loads(line)
    if "shares" not in msg:
        print(msg)                      # banner, or the final flag message
        if "flag" in msg:
            break
        continue
    secret = lagrange_at_zero(msg["shares"], msg["prime"])
    f.write((json.dumps({"secret": secret}) + "\n").encode())
    f.flush()
```

Why it is built this way:

- `socket.create_connection` opens the plain TCP connection. No TLS here.
- `s.makefile("rwb")` wraps the socket so Python handles line splitting for me. Iterating with `for line in f` gives exactly one JSON message per step, which is the right tool for a newline-delimited protocol. Doing this with raw `recv` would mean writing my own buffering, because one `recv` is not one message.
- `json.loads(line)` reads the real field names instead of guessing them. `msg["prime"]` and `msg["shares"]` cannot be wrong.
- `if "shares" not in msg` separates the banner and the final result from the actual rounds, so one loop handles everything the server might send.
- `json.dumps({"secret": secret}) + "\n"` sends the exact shape the error message asked for, with the newline the protocol needs to mark the end of the message.
- `f.flush()` is not optional. Python buffers writes, and without the flush the answer sits in memory while the server's twenty-second clock runs out.

### Running it

The file happened to be saved with a space in the name, so the command was:

```bash
python "python helios.py"
```

Why the quotes: the shell splits a command on spaces, so without them `python` would try to run a file called `python` and then complain about a separate argument `helios.py`. Quoting keeps the whole thing as one filename. Normally you would just name the file `helios.py` and run `python helios.py`.

Output:

```text
Connecting to 52.146.88.61:35719...
Connected!
>>> Sending: {"secret": 1133946792162907654}
>>> Sending: {"secret": 512345678901234567}
...
{"status": "unsealed", "rounds": 50, "flag": "prg{th3_qu0rum_h0lds_...}"}
```

All fifty rounds cleared. Each round is independent arithmetic on small integers, so the whole exchange finished far inside the twenty-second window - the network round trips took longer than the maths.

### One more trap: the placeholder flag

The first successful run returned this:

```text
flag{th3_qu0rum_h0lds_L0c4lb0x}
```

The platform rejected it. `L0c4lb0x` is a placeholder the challenge author ships for local testing. A live instance is supposed to mint a **per-team** flag instead. Getting the local one back means the container was not properly registered to the team - usually a stale or expired instance.

The fix was simply to start a fresh instance (this is where port `35719` came from) and run the same solver again. That run returned the real per-team flag, in the `prg{...}` format rather than `flag{...}`.

If a flag ever contains words like `local`, `test`, `fake`, or `example`, check whether it is the author's placeholder before spending time wondering why the submission failed.

### Flag

```text
prg{th3_qu0rum_h0lds_[A-Za-z0-9]{81794650194pOFbdjUR7a557c956eae70d5397a8cf261953502a0f41600_544}}
```

This one needed **one extra `}` at the end** to be accepted. The flag template contains a literal `{` from the `[A-Za-z0-9]{...}` part, so the closing braces do not pair up the way a reader expects. Submit exactly what the service printed.

### Why it works

A threshold secret-sharing scheme is nothing more than polynomial interpolation wearing a security hat. Once the field and a full quorum of points are handed to you, the secret is not hidden any more - it is determined. The "hard" part of the challenge is not the cryptography, it is the engineering: read the protocol correctly, keep the arithmetic inside the field, flush your writes, and finish fifty rounds before the clock stops.
