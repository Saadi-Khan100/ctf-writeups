# Breachmaster

## Understanding the challenge

|  |  |
| --- | --- |
| Category | Blue Team |
| Event | DPCH Online Qualifiers (Cydea Range platform) |
| Team | Pwnag3 |
| Files given | `mimikatz_hashdump.txt` (Mimikatz style LSASS credential dump) |

### What the challenge says

A Windows environment was compromised and the attacker dumped credentials out of memory. I get the output of that dump. I have to work out which service account the attacker went after, and recover its password in clear text.

The flag is only the password. Not the username, and not a `username:password` pair.

### What that format changes

This sounds like a small detail but it changes the work.

If the flag were `username:password`, getting the username right would be half the answer. Because the flag is only the password, the username is just a step along the way. I still have to identify the right account, since each account has its own credential, but what I submit at the end is one string.

It also tells me the password exists somewhere in a usable form. Either the dump has it in clear text, or it has a hash I can turn back into a password.

## Reading the dump

```bash
wc -l ~/Downloads/mimikatz_hashdump.txt
head -30 ~/Downloads/mimikatz_hashdump.txt
```

`wc -l` tells me how big the job is before I start. If it had been thousands of lines I would have gone straight to filtering. It is short enough to read, so I read it.

I always look at the head of a dump before writing any filter. Mimikatz output has a very specific shape, and if I guess that shape wrong my `grep` returns nothing. An empty result looks exactly the same as "there is nothing here", and that is a bad place to make a decision from.

The dump is `sekurlsa::logonpasswords` output. Each logon session looks like this:

```text
Authentication Id : 0 ; 123456 (00000000:0001e240)
Session           : Interactive from 1
User Name         : db_svc_account
Domain            : CORP
Logon Server      : DC01
Logon Time        : 11/4/2026 9:14:22 AM
SID               : S-1-5-21-...-1103
        msv :
         [00000003] Primary
         * Username : db_svc_account
         * Domain   : CORP
         * NTLM     : 7dfa0531d73101ca080c7379a9bff1c7
         * SHA1     : ...
        tspkg :
        wdigest :
         * Username : db_svc_account
         * Domain   : CORP
         * Password : (null)
```

### The structure is the whole challenge

Mimikatz prints one block per logon session. Inside each block it prints a smaller section for each security provider. The providers are `msv`, `tspkg`, `wdigest`, `kerberos` and `ssp`. Each one stores credentials differently, so each one gives a different kind of answer.

`msv` is the local authentication package. It holds NTLM and SHA1 **hashes**. It never holds a clear text password.

`wdigest` used to cache the clear text password in memory. On older or badly configured systems it still does, and then `* Password :` has the real password sitting there to be read.

So the first thing I checked was the `wdigest` section:

```text
        wdigest :
         * Password : (null)
```

`(null)` means WDigest credential caching is turned off on this machine. Microsoft disabled it by default years ago and this host has it disabled. The `tspkg` section is empty too.

That one word decides the whole route. There is no clear text password anywhere in this dump. The only credential material I have is the NTLM hash from `msv`, so the only way to a clear text password is to reverse that hash.

This is what separates this challenge from a simpler credential dump challenge. If `wdigest` had held a password, the answer would have been a single `grep`. Because it says `(null)`, there is real work to do.

## Finding the right account

```bash
grep -oP 'Username\s+:\s+\K\S+' ~/Downloads/mimikatz_hashdump.txt | sort -u
```

How this works:

- `-o` prints only the matching part instead of the whole line. I want the account name, not the Mimikatz formatting around it.
- `-P` turns on Perl compatible regular expressions, which is what makes `\K` available.
- `\K` is the useful piece. It tells the regex engine to throw away everything matched up to that point. So `Username\s+:\s+\K\S+` matches the label, the spaces, the colon and the spaces after it, then drops all of that and keeps only `\S+`, the run of non space characters that follows. The result is a bare username with no label stuck to it.
- `sort -u` removes duplicates, because every account appears several times across its provider sections.

Output:

```text
Administrator
db_svc_account
svc_backup
svc_sql
```

Four accounts, and I need one.

```bash
grep -iE 'svc_|db_|sql|service' ~/Downloads/mimikatz_hashdump.txt
```

The challenge says the attacker used a **service account**, so I filtered for the naming patterns service accounts use. `svc_` and `db_` are the common prefixes, and I added `sql` and `service` in case the naming was different here.

`-i` ignores case and `-E` turns on extended regular expressions so `|` works as "or".

Three of the four match. `Administrator` is the odd one out, and that is useful on its own, because `Administrator` is a built in local account and not a service account. The description rules it out.

That leaves `db_svc_account`, `svc_backup` and `svc_sql`. I separated them on two points.

**Which one has usable credential material.** An account only helps the attacker if its hash is actually present in the `msv` section. An account listed with an empty or missing `msv` block gives them nothing to work with.

**Which session type it had.** The `Session` line at the top of each block says how the account logged on. `Interactive from 1` means something logged on at the console or started as a service, and that is the kind of session whose secrets stay resident in LSASS memory. A network logon leaves far less behind.

`db_svc_account` is the one that fits. It is a database service account, it has an `Interactive from 1` session, and it has a populated `msv` block with an NTLM hash in it. A database service account is also the most valuable of the three to an attacker, because it usually has direct access to the data they came for.

## Pulling out the hash

```bash
grep -A5 'db_svc_account' ~/Downloads/mimikatz_hashdump.txt | grep NTLM
```

`-A5` prints the matching line plus the five lines after it. I needed it because the account name and the hash are on different lines. Mimikatz prints `* Username` first and the `* NTLM` line a few lines below it, so matching the username alone would never show me the hash.

Piping that into a second `grep NTLM` keeps only the hash line out of those five.

Output:

```text
         * NTLM     : 7dfa0531d73101ca080c7379a9bff1c7
```

A note on the NTLM field. On many dumps it comes back as two halves separated by a colon, `<LM half>:<NT half>`. The first half is the LM hash, and on any modern Windows build it is a fixed constant because LM hashing has been disabled for years, so it carries no information. The NT half is the one that matters. Here the dump gives the NT hash on its own, which is what I need.

## Cracking it with hashes.com

Instead of running a local wordlist attack I used **hashes.com**, which keeps a very large database of already cracked hashes and their plain text.

I went to `hashes.com/en/decrypt/hash`, pasted the hash into the box, and submitted it.

```text
7dfa0531d73101ca080c7379a9bff1c7
```

The result:

```text
Proceeded!
1 hashes were checked: 1 found 0 not found

Found:
7dfa0531d73101ca080c7379a9bff1c7:P@ssw0rd123!
```

The output format is `hash:plaintext`, so the password is `P@ssw0rd123!`.

### Why a lookup service works on this hash at all

This is the part worth understanding, because it does not work on every hash.

NTLM is computed as `MD4(password encoded as UTF-16LE)`. There is **no salt** anywhere in it. A salt is a random value mixed into the password before hashing, and it is different for every account, which means the same password produces a different hash each time.

NTLM has none of that. So the password `P@ssw0rd123!` produces the hash `7dfa0531d73101ca080c7379a9bff1c7` on every Windows machine in the world, forever. Once somebody has cracked it once and put the pair into a database, nobody ever has to crack it again. They just look it up.

That is why a site with a big enough database answers in under a second for a common password, while a local wordlist attack would have to walk through millions of candidates to find the same thing.

I can verify the pair myself without any tool:

```bash
python3 -c "
from Crypto.Hash import MD4
print(MD4.new('P@ssw0rd123!'.encode('utf-16le')).hexdigest())
"
```

```text
7dfa0531d73101ca080c7379a9bff1c7
```

Same hash. So the lookup is correct and I am not trusting the site blindly.

The encoding matters here. `utf-16le` means each character takes two bytes, little endian, which is how Windows stores text internally. Hashing the plain ASCII bytes instead gives a completely different value and the check would fail for no obvious reason.

The password itself is a classic service account password. A dictionary word, a capital at the front, `@` swapped for `a`, `0` swapped for `o`, digits on the end and a symbol to satisfy the complexity policy. It looks strong to a policy checker and it sits in every cracked password database, because the substitution rules are completely predictable.

### Flag

The flag is the password on its own, with no username.

```text
flag{P@ssw0rd123!}
```

### The fix

Three separate things went wrong on this host, and they need three separate fixes.

**The hash should not have been readable.** Dumping credentials out of LSASS needs `SeDebugPrivilege` and an unprotected LSASS process. Turning on LSA Protection, which runs LSASS as a protected process, blocks ordinary tools from opening it. Credential Guard goes further and moves the secrets into a separate virtualised container that the operating system itself cannot read.

**The password should not have been in a lookup database.** `P@ssw0rd123!` passes a complexity policy and fails a reality check. Complexity rules measure the wrong thing, because they count character classes instead of guessability. Checking new passwords against a breached password list is what actually stops this. For service accounts the better answer is Group Managed Service Accounts, where Windows generates a 120 character random password and rotates it automatically, so there is nothing for anyone to look up.

**The account was probably over-privileged.** A database service account with an interactive session on a workstation is worth stealing. Service accounts should be restricted to logging on as a service, denied interactive and network logon rights where they do not need them, and scoped to the one machine they run on.

Note that WDigest being off is the one thing this host did right. It is why the dump shows `(null)` instead of handing over the password directly.

---

[Back to this event](README.md) · [All writeups](../README.md)
