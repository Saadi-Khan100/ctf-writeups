# What I learned

These are the mistakes that actually cost time during these four solves. They are written down because every one of them will happen again otherwise.

### Save the data before you study it

Promise prints its public key and ciphertext once and then hangs up, and the flag is encrypted inside that dump. That means the challenge becomes an offline puzzle the moment the output is in a file. I lost two instances to expiry before realising this and starting with `tee`.

**If a service dumps data once, your first command writes it to disk.** Analysis comes second.

### TCP gives you bytes, not messages

This bit me twice in different ways.

In Helios Vault, one `recv` does not mean one JSON line. You have to collect bytes in a buffer until you actually hold a newline, then cut one line off the front and keep the rest. Scripts that assume "one recv equals one message" work on a fast local test and fail against a real server.

In Meeeps it was the opposite direction. `readnum` calls `read(0, buf, 0x1f)`, so I padded every number to exactly 31 bytes and fired 256 requests at once to make the stack scan fast. At a TCP segment boundary one `read` returned fewer than 31 bytes, every block after it shifted, and eventually a fragment was parsed as menu option 3. The program performed a garbage write and exited, and the script died with a confusing `EOFError`.

**Padding only keeps you in sync if the whole block arrives in one piece, and nothing guarantees that.** Unless the protocol has its own delimiters, send one request and wait for its answer.

### Small library details will waste your time

`printf("%p", 0)` prints `(nil)`, not `0x0`. My stack scan hit a zero word twenty bytes in and crashed on a regex that returned `None`. Thirty seconds to fix, one live instance gone.

`telnetlib` was removed in Python 3.13 and the Kali machine was on 3.14, so the usual interactive shell helper did not exist. The obvious replacement, `select()` on stdin, only works with sockets on Windows, so it broke on the other machine. A short threaded reader works everywhere and should have been the first version.

### One successful run is not a test

The first Promise key recovery worked perfectly on the key I happened to generate. Across eight fresh keys it failed one time in five, because a single bad prime dragged a gcd down to 1. Adding validation and a retry from a different starting index took it to eight out of eight.

**Before going live, run your solver against several freshly generated inputs.** If the handout contains the generator, there is no excuse not to.

### Trust the tool's output, not your idea of it

Lattice reduction returns the *primitive* vector, which means it quietly divides out any common factor. I assumed the value I got back was the exact multiplier, divided by it, and ended up with a modulus that was 1807 bits instead of 1803. Nothing errored; it just produced wrong primes further down. Building the modulus from a gcd of several independent values removed the assumption entirely.

### Submit the flag exactly as printed

Both Helios Vault and Meeeps returned flags containing leftover template text like `[A-Za-z0-9]{8`, and Helios also needed a second closing brace. They look broken. They are the real flags and any attempt to tidy them up is rejected.

**Paste what the service gave you, character for character, before trying any variation.**

### Run it locally if you possibly can

The clearest contrast between these four. For Promise I could run the handout locally, generate fresh keys and verify the whole attack eight times before touching the remote, so the live run worked on the first try and finished in 0.06 seconds. For Meeeps there was no MIPS emulator available, so the exploit was written blind, and both of the small bugs above only surfaced against a live service on a timer.

When the handout can be run locally, run it. When it cannot, assume the first two attempts are reconnaissance, and print enough output that a single transcript tells you what went wrong.

---

[← All DPCH Online Qualifiers writeups](README.md)
