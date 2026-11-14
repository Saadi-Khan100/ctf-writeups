#!/usr/bin/env python3
"""
Promise - full offline solver.

    python3 promise_solver.py promise_out.txt

The scheme publishes  t_i = (p_i^-1 mod g) - u  (mod g)  for 150 secret 45-bit
primes p_i, with g (~2^1803) and u kept secret, and encrypts a sparse vector e
as c1 = sum e_i*t_i over the integers.

Over Z the key satisfies  p_i*t_i + p_i*u - 1 = K_i*g  with K_i ~ 2^45, hence
for any pair  X_ij = p_i*p_j*(t_i-t_j) - (p_j-p_i) = m_ij*g,  m_ij ~ 2^88.
Eliminating g between the pairs (i,j) and (i,k) leaves

    A*(t_i-t_j) + B*(t_i-t_k) = R,   A = m_ik*p_j,  B = -m_ij*p_k,  R ~ 2^88

with |A|,|B| ~ 2^131.  That is a rank-2 lattice whose Gaussian minimum is about
2^920, so the relation is shorter than random by ~2^790 and Lagrange-Gauss
reduction returns it exactly.  Sweeping k keeps p_j as a factor of every A, so
a gcd peels the prime out with no factoring at all; the recovered primes then
turn each X_ij into a known multiple of g, and a second gcd gives g.
"""
import re
import sys
from hashlib import sha256, shake_256
from math import gcd


#!/usr/bin/env python3
"""
Promise - key recovery.

Scheme:  pk_i = t_i = (p_i^-1 mod g) - u  (mod g),  p_i ~ 2^45 primes, g ~ 2^1803 secret.
         c1 = sum e_i*t_i  (over Z, no reduction), c2 = sum e_i.

Key relations (exact over Z):
    p_i*t_i + p_i*u - 1 = K_i*g                      with K_i ~ 2^45
    X_ij := p_i*p_j*(t_i-t_j) - (p_j-p_i) = m_ij*g   with m_ij = K_i*p_j - K_j*p_i ~ 2^88

Eliminating g between the pairs (i,j) and (i,k) gives
    A*(t_i-t_j) + B*(t_i-t_k) = R,   A = m_ik*p_j, B = -m_ij*p_k, R ~ 2^88
with |A|,|B| ~ 2^131 -- absurdly short for a rank-2 lattice whose Gaussian
minimum is ~2^920, so Lagrange-Gauss reduction returns it exactly.

Varying k keeps the factor p_j in A and m_ij in B, so a gcd over several k
peels them out with no factoring at all.
"""


def norm2(v):
    return sum(x * x for x in v)


def gauss_reduce(b1, b2):
    while True:
        if norm2(b1) > norm2(b2):
            b1, b2 = b2, b1
        n1 = norm2(b1)
        if n1 == 0:
            return b1, b2
        dot = sum(x * y for x, y in zip(b1, b2))
        mu = (2 * dot + n1) // (2 * n1) if dot >= 0 else -((-2 * dot + n1) // (2 * n1))
        b2 = tuple(y - mu * x for x, y in zip(b1, b2))
        if norm2(b2) >= norm2(b1):
            return b1, b2


def recover_pair(ts, i, j, ks, C=1 << 42):
    """returns (p_j, m_ij) via gcd over several auxiliary indices k"""
    D_ij = ts[i] - ts[j]
    gA = gB = 0
    for k in ks:
        D_ik = ts[i] - ts[k]
        r1, _ = gauss_reduce((1, 0, C * D_ij), (0, 1, C * D_ik))
        gA = gcd(gA, r1[0])
        gB = gcd(gB, r1[1])
    return abs(gA), abs(gB)


def _is_prime(x):
    if x < 2:
        return False
    for q in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if x % q == 0:
            return x == q
    d, r = x - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        v = pow(a, d, x)
        if v in (1, x - 1):
            continue
        for _ in range(r - 1):
            v = v * v % x
            if v == x - 1:
                break
        else:
            return False
    return True


def recover_key(ts, b=40, beta=5, gbits=1803):
    """Recover (ps, g, u) from the public key alone."""
    n = len(ts)
    lo, hi = 1 << b, 1 << (b + beta)

    def aux(exclude, want=6):
        return [k for k in range(n) if k not in exclude][:want]

    def get_p(i, j):
        """p_j, validated"""
        pj, _ = recover_pair(ts, i, j, aux((i, j)))
        return pj if lo <= pj < hi and _is_prime(pj) else None

    for base in range(min(n, 12)):                      # try several base indices
        p_base = get_p(base ^ 1 if base ^ 1 < n else 0, base)
        if p_base is None:
            continue

        # Every X = p_base*p_j*(t_base - t_j) - (p_j - p_base) is an exact
        # multiple of g; the cofactors are ~2^88 and essentially random, so a
        # gcd over a handful of j lands on g itself.  Keep only the ones that
        # do not destroy the gcd -- a bad p_j would collapse it to 1.
        g = 0
        for j in range(n):
            if j == base:
                continue
            pj = get_p(base, j)
            if pj is None:
                continue
            X = p_base * pj * (ts[base] - ts[j]) - (pj - p_base)
            ng = gcd(g, X) if g else abs(X)
            if ng.bit_length() < gbits - 8:
                continue                                 # reject this one
            g = ng
            if gbits - 8 <= g.bit_length() <= gbits + 8:
                break

        if not g or not (gbits - 8 <= g.bit_length() <= gbits + 8):
            continue
        for q in (2, 3, 5, 7, 11, 13):                   # shed small cofactors
            while g % q == 0 and (g // q).bit_length() >= gbits:
                g //= q

        try:
            u = (pow(p_base, -1, g) - ts[base]) % g
            ps = []
            for t in ts:
                pi = pow((t + u) % g, -1, g)
                if not lo <= pi < hi:
                    raise ValueError
                ps.append(pi)
        except Exception:
            continue
        return ps, g, u

    raise ValueError('key recovery failed')


def reconstruct(a, b_):
    r0, r1 = a, b_
    v0, v1 = 0, 1
    c = r0 // r1
    r0, r1 = r1, r0 - c * r1
    v0, v1 = v1, v0 - c * v1
    while r1 * r1 >= a:
        c = r0 // r1
        r0, r1 = r1, r0 - c * r1
        v0, v1 = v1, v0 - c * v1
    return v1, r1


def decrypt(sk, ct, n):
    ps, g, u = sk
    c1, c2 = ct
    s = (c1 + u * c2) % g
    den, num = reconstruct(g, s)
    if den < 0:
        den, num = -den, -num
    ks = [i for i, p in enumerate(ps) if den % p == 0]
    prod = 1
    for i in ks:
        prod *= ps[i]
    scale = prod // den
    den, num = prod, num * scale
    e = [0] * n
    for i in ks:
        p = ps[i]
        e[i] = num * pow(den // p % p, -1, p) % p
    return e


def main(path):
    txt = open(path).read()
    pk = [int(x) for x in re.search(r'pk\s*=\s*\[(.*?)\]', txt, re.S).group(1).replace('\n', '').split(',')]
    c1 = int(re.search(r'c1\s*=\s*(\d+)', txt).group(1))
    c2 = int(re.search(r'c2\s*=\s*(\d+)', txt).group(1))
    enc = bytes.fromhex(re.search(r'enc\s*=\s*([0-9a-fA-F]+)', txt).group(1))
    print(f'[*] {len(pk)} public values, c1 {c1.bit_length()} bits, {len(enc)} flag bytes')

    ps, g, u = recover_key(pk)
    print(f'[+] secret key recovered: g is {g.bit_length()} bits')

    e = decrypt((ps, g, u), (c1, c2), len(pk))
    assert sum(x * y for x, y in zip(e, pk)) == c1 and sum(e) == c2, 'plaintext mismatch'
    print(f'[+] plaintext recovered: weight {sum(1 for x in e if x)}')

    key = sha256(f"1|{e}|{(c1, c2)}".encode()).digest()
    flag = bytes(x ^ y for x, y in zip(enc, shake_256(key).digest(len(enc))))
    print('\nFLAG:', flag.decode(errors='replace'))


main(sys.argv[1] if len(sys.argv) > 1 else 'promise_out.txt')
