# Promise

## Understanding the challenge

|  |  |
| --- | --- |
| Category | Crypto |
| Event | DPCH Online Qualifiers (Cydea Range platform) |
| Team | Pwnag3 |
| Target | `nc 52.146.88.61 36518` - raw TCP, dumps and closes |
| Files given | `crypto-promise.tar.gz` (contains `chall.py`) |

### What the challenge says

"Some promises are harder to keep than others." That is the whole description. Everything else has to come from the source.

### Opening the files

```bash
tar -xzf crypto-promise.tar.gz -C promise/
cat promise/chall.py
```

`tar -xzf` unpacks the archive (`x` extract, `z` gzip, `f` from this file) and `-C promise/` puts it in its own folder. Then I read the source, because in a crypto challenge the source *is* the challenge.

### Capture the data before anything else

One thing became obvious as soon as I read the code: the service prints the public key and the ciphertext once and then closes. The flag is XOR-encrypted inside that dump. That means **once you have the output saved to a file, the challenge is yours forever** - the instance can expire and you can still solve it offline.

So the very first live command was not an attack, it was a capture:

```bash
nc 52.146.88.61 36518 | tee promise_out.txt
```

Why `tee`: it prints the output to the screen *and* writes it to a file at the same time. If you only use `nc` and the terminal scrolls away, the data is gone and the box may already be dead.

When `nc` refused to connect from one machine, I used plain Python instead, which worked:

```bash
python -c "import socket;s=socket.socket();s.settimeout(20);s.connect(('52.146.88.61',36518));d=b'';s.settimeout(8)
while True:
    c=s.recv(65535)
    if not c: break
    d+=c
open('promise_out.txt','wb').write(d);print(len(d),'bytes')"
```

That saved about 82 KB. After that the timer stopped mattering.

### The dumper script I actually used

Typing `nc` by hand was unreliable, because the service sends about 80 KB in one burst and then closes. If the terminal is still scrolling when the instance dies, part of it is lost. So I wrote a tiny dumper, `get_promise.py`:

```python
import socket

HOST = "52.146.88.61"
PORT = 36518

s = socket.socket()
s.settimeout(30)
s.connect((HOST, PORT))

data = b""
while True:
    try:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    except:
        break

open("promise_output.txt", "wb").write(data)
print("Saved", len(data), "bytes")
print(data[:300].decode(errors="replace"))
s.close()
```

Line by line, why each piece is there:

- `s.settimeout(30)` - if the box is slow I still wait, but I never hang forever.
- `while True` with `s.recv(65536)` - one `recv` does **not** give one message. TCP is a stream, so the data arrives in whatever chunk sizes the network feels like. I keep calling `recv` and glueing the pieces together.
- `if not chunk: break` - an empty return means the server closed the connection. That is my signal that the dump is complete.
- `except: break` - when the timeout fires, I stop instead of crashing, so whatever I already collected still gets written.
- `open(..., "wb").write(data)` - written in **binary** mode. I had not decoded anything yet, so I save the raw bytes exactly as they came and decode later. This avoids a decode error throwing away the whole capture.
- `print(data[:300]...)` - a quick eyeball check that I got `params = (150, 20, 40, 5)` and the start of `pk`, rather than an error page.

Run it:

```bash
python get_promise.py
```

```text
Saved 82550 bytes
params = (150, 20, 40, 5)
pk = [6007332254050702518902538755368964661336013119717654779359580551...
```

### Three captures, two instances

The instance expired while I was still debugging the solver, so I ended up with three dump files. Each instance has its **own** key, and therefore its own flag, so it matters which file gets solved:

| File | Instance | Result |
| --- | --- | --- |
| `promise_output.txt` | first instance | solves, but that instance was already dead - flag not accepted |
| `output.txt` | second instance | solves, same flag as below |
| `promise_out.txt` | second instance | **this is the one that gave the accepted flag** |

`output.txt` and `promise_out.txt` are two saves of the same live instance, so they decrypt to the identical flag. Only the first file is from a different run.

Label your captures with the port or the time. Once the instance is gone you cannot tell them apart by looking, and solving the wrong one wastes a full run.

### How the scheme works

The scheme uses these numbers:

| Name | Size | Secret? |
| --- | --- | --- |
| `p_1 ... p_150` | 150 primes, each 40-45 bits | yes |
| `g` | about 1803 bits | yes |
| `u` | random, less than `g` | yes |
| `t_1 ... t_150` | the public key | no |

The public key is built like this:

```latex
t_i \equiv p_i^{-1} - u \pmod g
```

So each public number is the modular inverse of a secret prime, shifted by a secret amount `u`. That is all an attacker is given - 150 shifted inverses.

To encrypt, the program picks a sparse vector `e` with exactly 20 non-zero entries, each below 2^40, and sends two numbers:

```latex
c_1 = \sum_i e_i t_i, \qquad c_2 = \sum_i e_i
```

Notice that `c1` is an ordinary integer sum. There is no `mod g` anywhere in the encrypt function. Keep that in mind, it comes up later.

To decrypt, the owner adds the shift back and the `u` cancels out:

```latex
s \equiv c_1 + u c_2 \equiv \sum_i e_i p_i^{-1} \pmod g
```

That sum of fractions is a single rational number. Its denominator is the product of the 20 primes that were used, about 2^900, and the numerator is about the same size. Because `g` is 1803 bits, which is more than twice 900, there is exactly one such fraction and it can be recovered. The program does this with a routine called `reconstruct`, then works out which primes divide the denominator, and from that rebuilds `e`.

Finally the key is `sha256("1|" + str(e) + "|" + str(ct))` and the flag is XORed with SHAKE-256 of that key.

### What I actually need

The key depends on `e` exactly. Getting "most of" `e` is worth nothing. So the goal is clear: recover the exact plaintext vector, which means either breaking the ciphertext directly or recovering the private key.

## The first idea fails, the second one wins

### The obvious attack

Look at the ciphertext again:

```latex
c_1 = \sum_i e_i t_i
```

I know all 150 values of `t`, I know `c1`, and only 20 of the `e` values are non-zero and each is small. This looks exactly like a knapsack problem, and knapsack problems with small answers usually fall to lattice reduction (LLL). So that is what I tried first.

It does not work. Here is why.

### Why it fails

All the vectors `x` with `sum x_i t_i = 0` form a lattice. Think of a lattice as a grid of points in many dimensions. Any solution to my equation is my answer plus some point of that grid, so if I can find the shortest point I usually find the answer.

Here the grid has 149 dimensions and its determinant is about 2^1803. There is a standard estimate for how short the shortest point of such a grid is:

```latex
\det(L)^{1/149} \cdot \sqrt{149 / 2\pi e} \approx 2^{13.7}
```

My answer `e` has size about 2^42. So the grid is full of points that are roughly 2^28 times **shorter** than the thing I am hunting. In fact there are something like 2^4000 grid points shorter than my answer. Lattice reduction will cheerfully hand me one of those, and none of them is the plaintext.

The plaintext is still the only *valid* answer, because it must be sparse, non-negative and bounded. But a lattice has no way to express "only 20 entries may be non-zero". That is why this is a sparse subset-sum problem, not a short-vector problem, and why the ciphertext route is a dead end.

So I leave the ciphertext alone and attack the public key instead.

### Writing the key as plain integers

The trick that unlocks everything is to stop thinking "modulo g" and write the relation as an exact equation over normal integers. Saying

```latex
t_i \equiv p_i^{-1} - u \pmod g
```

is the same as saying there is some whole number `K_i` with

```latex
p_i t_i + p_i u - 1 = K_i g
```

Sizes are the interesting part. `p_i` is about 45 bits. `K_i` is roughly `p_i (t_i + u) / g`, which is also about 45 bits. So this equation has two small unknowns and two big ones.

### Step one: get rid of u

Take two indices `i` and `j`. Multiply the `i` equation by `p_j`, multiply the `j` equation by `p_i`, and subtract. The `u` terms become identical and cancel:

```latex
X_{ij} = p_i p_j (t_i - t_j) - (p_j - p_i) = m_{ij} \, g, \qquad m_{ij} = K_i p_j - K_j p_i
```

This says something strong: **every pair of public values gives an exact multiple of the secret modulus `g`**, and the multiplier `m_ij` is only about 88 bits.

Before building anything on this, I generated a key locally with the challenge's own `keygen()` and checked the equation numerically. It held exactly. That check took two minutes and saved hours.

The problem is that `X_ij` still contains unknowns. I know `t_i - t_j`, but not the primes and not `g`.

### Step two: get rid of g

So do the same trick again. Take two pairs that share an index, `(i,j)` and `(i,k)`. Each gives a multiple of `g`. Cross-multiply them by each other's multipliers so that `g` cancels, then divide through by `p_i`. What is left is:

```latex
A \,(t_i - t_j) + B \,(t_i - t_k) = R, \qquad A = m_{ik} p_j, \;\; B = -m_{ij} p_k
```

where `A` and `B` are about 2^131 and the leftover `R` is only about 2^88.

### Why this breaks the scheme

This is a relation between two numbers I know (`t_i - t_j` and `t_i - t_k`) using two unknown but *small* multipliers. That is a 2-dimensional lattice problem, and 2-dimensional lattices are easy.

How easy? The lattice built from these two differences has a determinant of about 2^1843, so a random short vector in it would be around 2^920. Ours is 2^131. My target is shorter than a random vector by a factor of roughly 2^790.

When a vector sticks out that much, you do not need LLL or any library. Lagrange-Gauss reduction, which is about ten lines of integer arithmetic, finds it exactly every time.

## Recovering the key and the flag

### The trick that removes all the factoring

The reduction gives me `A = m_ik * p_j`. The prime I want is hidden inside a 131-bit product. The slow way is to factor that number. The fast way is to notice what stays the same.

Fix `i` and `j`, then change only `k`. Every run gives a different `A`, but **every one of them still contains `p_j` as a factor**, multiplied by a different random-looking 88-bit number. So take the greatest common divisor of several of them and everything except `p_j` cancels out.

```python
def gauss_reduce(b1, b2):
    while True:
        if norm2(b1) > norm2(b2):
            b1, b2 = b2, b1
        n1 = norm2(b1)
        if n1 == 0:
            return b1, b2
        dot = sum(x * y for x, y in zip(b1, b2))
        mu = (2*dot + n1) // (2*n1) if dot >= 0 else -((-2*dot + n1) // (2*n1))
        b2 = tuple(y - mu*x for x, y in zip(b1, b2))
        if norm2(b2) >= norm2(b1):
            return b1, b2

def recover_pair(ts, i, j, ks, C=1 << 42):
    """returns (p_j, m_ij) by gcd over several helper indices k"""
    D_ij = ts[i] - ts[j]
    gA = gB = 0
    for k in ks:
        D_ik = ts[i] - ts[k]
        r1, _ = gauss_reduce((1, 0, C*D_ij), (0, 1, C*D_ik))
        gA = gcd(gA, r1[0])     # collapses to p_j
        gB = gcd(gB, r1[1])     # collapses to m_ij
    return abs(gA), abs(gB)
```

About `C = 1 << 42`: the lattice has three columns and I need the third one (the leftover `R`) to weigh about the same as the first two, otherwise the reduction optimises the wrong thing. 2^42 does that. I tested 2^40, 2^42 and 2^45 and all three returned the same vector, so the choice is not delicate.

Testing this against a locally generated key:

```text
gcd of A values = 21778071482940061  (45 bits)
true p_j        = 21778071482940061
gcd of B values = 158456325028528675187087900673  (87 bits)
true m_ij       = 158456325028528675187087900673
```

Both exact, and no factoring was involved anywhere.

### Getting g

Once two primes are known, `X_ij` is a number I can actually compute, and I already proved it is an exact multiple of `g`. Compute a few of them from different pairs and take the gcd. The multipliers are random 88-bit numbers so they share no common factor, and the gcd lands on `g` itself.

**The trap I fell into.** My first version computed `g = X_ij / m_ij` using the multiplier from the `B` column. It gave a 1803-bit answer sometimes, and 1807 bits other times. The reason is that lattice reduction always returns the *primitive* vector - if `A` and `B` share a common factor, it divides both of them by it. So the multiplier comes back slightly too small, and `g` comes out as a small multiple of the real one. Everything after that silently produced garbage primes.

The fix is to never trust a single reduced value. Build `g` from a gcd of independent multiples, check every prime for range and primality before using it, and throw away any value that drags the gcd below 1795 bits:

```python
g = 0
for j in range(n):
    pj = get_p(base, j)                 # validated: 40-45 bits and prime
    if pj is None:
        continue
    X = p_base*pj*(ts[base] - ts[j]) - (pj - p_base)
    ng = gcd(g, X) if g else abs(X)
    if ng.bit_length() < gbits - 8:
        continue                        # a bad prime would collapse the gcd
    g = ng
    if gbits - 8 <= g.bit_length() <= gbits + 8:
        break
```

There is also a retry loop around the whole thing that tries a different starting index when one fails. This is not decoration. My first version always started from index 0, and about one run in five failed because one bad prime ruined the gcd. With validation and retry it went to eight successes out of eight.

### Finishing the key

Once `g` is known the rest is two lines:

```python
u  = (pow(p_base, -1, g) - ts[base]) % g
ps = [pow((t + u) % g, -1, g) for t in pk]
```

The first line undoes the shift using a prime I trust. The second line recovers all 150 primes by inverting each public value. Every one of them must land back between 2^40 and 2^45 - if even one does not, `g` is wrong and I should not continue.

### Decrypting

Now I can paste the challenge's own `reconstruct()` and `decrypt()` straight from `chall.py`, unmodified, and run them with my recovered key:

```python
e = decrypt((ps, g, u), (c1, c2), len(pk))
assert sum(x*y for x, y in zip(e, pk)) == c1 and sum(e) == c2
key  = sha256(f"1|{e}|{(c1, c2)}".encode()).digest()
flag = bytes(x ^ y for x, y in zip(enc, shake_256(key).digest(len(enc))))
```

The `assert` re-encrypts my recovered plaintext and checks it reproduces the original ciphertext. If that passes, the answer is certainly right.

### The attempt that did not work

Before the lattice approach there was an earlier script, `solve.py`, built on **continued fractions** instead.

The idea was reasonable. The relation I want is a ratio of two big numbers where the hidden numerator and denominator are small. Continued fractions are the classic tool for exactly that: expand `delta[anchor] / delta[j]` and the best small approximations fall out as convergents.

```python
CF_LIMIT = 1 << 137

def largest_small_convergent(a, b):
    p0, p1, q0, q1 = 0, 1, 1, 0
    best = None
    while b:
        k = a // b
        a, b = b, a - k * b        # one step of Euclid
        p0, p1 = p1, k * p1 + p0   # build numerator
        q0, q1 = q1, k * q1 + q0   # build denominator
        if p1 and abs(p1) < CF_LIMIT and q1 < CF_LIMIT:
            best = (sign * p1, q1)
    return best
```

It did recover the primes. The script prints `[+] p[0] bits: ...` and that part worked. But look at how it ends:

```python
# Rest of recovery (q, g, u, e) - abbreviated for now
print("[+] Primes recovered. Full decrypt logic can be completed if this succeeds.")
```

It never got to `g`, never got to `u`, and never decrypted anything. It was a half-finished experiment that I stopped because the two-dimensional lattice reduction does the same job in one step, more reliably, and without needing a separate `CF_LIMIT` tuned by hand.

**Why continued fractions are weaker here.** A continued fraction finds good approximations to a ratio of **two** numbers. My relation involves **three** quantities tied together, so to use it I had to pick one pair at a time and hope the convergent list contained the right entry. Lagrange-Gauss reduction on the rank-2 lattice finds the shortest vector *directly* and *provably*, with no threshold to guess. Once that was written, `solve.py` had nothing left to offer.

### Running it

```bash
python3 promise_solver.py promise_out.txt
```

```text
[*] 150 public values, c1 1845 bits, 116 flag bytes
[+] secret key recovered: g is 1803 bits
[+] plaintext recovered: weight 20

FLAG: crypto{r4t10s_0f_sh1ft3d_1nv3rs3s_c0nv3rg3_t0_th3_k3y...}
```

Total runtime 0.06 seconds, offline, from the saved file.

### Flag

```text
crypto{r4t10s_0f_sh1ft3d_1nv3rs3s_c0nv3rg3_t0_th3_k3y1794664179McyqxN1ze3e078b95daf2a6e7c6e5cb3e2988e1cf7f005b0_544}
```

The flag text describes the attack exactly: ratios of shifted inverses converge to the key.

### Why it works

The scheme hides `u` and `g` behind the public values, but it cannot hide the *relationships* between them. Any two public values, written as plain integers, give an equation whose unknowns are tiny compared to the modulus. Two such equations together remove the modulus entirely and leave a relation so short that a 2-dimensional lattice finds it instantly. The security assumption quietly required those relations to be hard to spot, and they were not.
