# Plainwire

## Understanding the challenge

|  |  |
| --- | --- |
| Category | Blue Team / Intrusion Reconstruction |
| Event | DPCH Online Qualifiers (Cydea Range platform) |
| Team | Pwnag3 |
| Files given | Log collection for the Northbridge Institute of Technology incident (endpoint, auth, VPN, web) |
| Flag format | `FLAG{username:password}` |

### What the challenge says

Northbridge Institute of Technology was breached in a seven stage intrusion. The attacker exploited an edge appliance, dropped an ASPX web shell on the web server, dumped credentials from memory, moved sideways using one of the recovered accounts, installed persistence, staged and exfiltrated finance data, and then wiped and encrypted systems.

The flag is a username and its password, with a colon between them.

### Reading the format first

The format tells me a lot here.

`FLAG{username:password}` means the answer is a cleartext credential pair, not a hash. So somewhere in this evidence there is a password sitting in plain text. And out of the seven stages described, only one of them produces cleartext credentials, which is the credential dumping stage.

That cut a large log collection down to one question before I opened anything. Where is the memory dump output, and which of the accounts in it was actually used afterwards?

The second half of that question is the real work. A credential dump holds every account that had a session on the machine, which is usually ten or more. Only one of them got reused for lateral movement. The dump gives me a list of candidates. The authentication logs tell me which candidate is the answer.

## Step 1: finding the credential dump output

```bash
find . -type f \( -iname '*lsass*' -o -iname '*mimikatz*' -o -iname '*hashdump*' \) 2>/dev/null
```

What this does and why I wrote it this way:

`-iname` is the case insensitive version of `-name`. Evidence files come from different tools, and I do not want to miss `LSASS_dump.txt` just because I searched in lowercase.

The `\( ... -o ... \)` groups the three patterns together with "or". Without the brackets, `find` applies `-type f` to only the first pattern and the logic breaks.

`2>/dev/null` hides permission errors on folders I cannot read, so the real matches are not buried in noise.

I searched for three different names because credential dumping leaves its output named after whichever tool produced it. `lsass` covers a process dump of LSASS, which is the Windows process that holds logon secrets. `mimikatz` and `hashdump` cover the tools that parse that dump.

Result:

```text
./logs/endpoint/SRV-WEB01_lsass_dump.txt
```

One file, and it is on `SRV-WEB01`. That fits the chain in the description, because the web shell landed on the web server, so the first credential dump should come from that same host.

## Step 2: reading the dump structure

```bash
head -50 logs/endpoint/SRV-WEB01_lsass_dump.txt
wc -l logs/endpoint/SRV-WEB01_lsass_dump.txt
```

I always read the head of an unknown artifact before I write any filter. If I guess the layout and write a `grep` pattern that does not match, I get an empty result and no explanation. An empty result looks exactly like "there is nothing here", which is a bad place to make a decision from.

The file is Mimikatz `sekurlsa::logonpasswords` output. Each logon session looks like this:

```text
User Name         : svc_backup
Domain            : NIT
         * Username : svc_backup
         * Domain   : NIT
         * Password : B4ckup!2026
```

The structure matters. Mimikatz prints one block per logon session, and inside each block it prints a smaller block for each security provider. The providers are `msv`, `tspkg`, `wdigest`, `kerberos` and `ssp`. The `* Username` and `* Password` lines are the entries inside those provider blocks.

Two things about this output are worth knowing, because they decide whether a challenge like this is solvable at all.

`msv` gives NTLM and SHA1 hashes. It never gives a cleartext password.

`wdigest` and `tspkg` can give the cleartext password, but only on systems where WDigest caching was left turned on.

So when a dump shows `* Password :` with real text next to it instead of `(null)`, that machine had WDigest credential caching enabled. That is the only reason this challenge has a cleartext answer. On a properly hardened host every `Password` field reads `(null)`, and then the only way forward is cracking a hash.

## Step 3: pulling out every candidate pair

```bash
grep -E '\* Username|\* Password' logs/endpoint/SRV-WEB01_lsass_dump.txt | paste - -
```

How this works:

`grep -E '\* Username|\* Password'` keeps only the two line types I need. The `\*` is an escaped asterisk. In a regular expression a bare `*` means "repeat the previous thing", so without the backslash the pattern does not mean what it looks like.

`paste - -` is the useful part. `paste` joins lines side by side, and each `-` means "read one line from standard input". Two dashes means it takes the lines in pairs and prints each pair on one line, separated by a tab. Since the dump always prints `Username` immediately followed by `Password`, this turns the output into a readable two column table instead of forty alternating lines.

The result is ten account and password pairs, including:

```text
* Username : svc_backup       * Password : B4ckup!2026
* Username : sql_svc          * Password : S3cureSql#2026
* Username : admin_local      * Password : LocalAdmin!2025
...
```

Ten candidates, and the flag takes one of them. Nothing in the dump itself says which account the attacker went on to use. A dump is only a snapshot of who happened to have a session on that machine, and most of those sessions are ordinary service accounts doing their normal job.

This is the point where it would be easy to guess. `admin_local` has "admin" in the name and looks like the most valuable account. `svc_backup` looks like a routine backup service. Picking by which name sounds the most important is a coin flip, and the evidence here can settle it properly.

## Step 4: finding which account was actually reused

The description says the attacker "moved laterally with the recovered service account". Lateral movement means authentication on a different host than the one that was dumped. So for each candidate I asked one question. Does this account show up in authentication logs on other machines, after the dump?

```bash
grep -r 'svc_backup' logs/ 2>/dev/null | head -30
```

`-r` searches recursively through every file under `logs/`, so I do not need to know in advance which log holds the answer. The evidence is spread across endpoint, auth, VPN and web logs, so searching all of them at once saves me guessing.

`head -30` caps the output. A reused service account can appear hundreds of times, and I only need to see what kinds of places it appears in.

The hits land in three different log sources:

```text
logs/auth/windows_security.log:  4624: An account was successfully logged on.
    Account Name: svc_backup
    Logon Type: 3
    Source Network Address: 10.1.2.15

logs/vpn/vpn.log:  Successful authentication for user svc_backup from 203.0.113.44

logs/endpoint/SRV-FIN01_security.log:
    Lateral movement detected - svc_backup used for remote service installation
```

Reading those three in order gives me the whole lateral movement stage.

**Event 4624 with Logon Type 3.** 4624 is a successful logon. The logon type is the part that matters. Type 3 is a network logon, which is what you get from SMB, from a remote service, or from `PsExec`. An interactive console login is type 2, and an RDP session is type 10. So type 3 means this account was used to reach the machine over the network, not by somebody sitting in front of it. That is the signature of lateral movement with a stolen credential.

**The VPN log.** The same account authenticating from `203.0.113.44`, which is an external address. A backup service account has no business logging in through the VPN from the internet. Service accounts run locally under the service control manager. They do not dial in.

**`SRV-FIN01_security.log`.** The account shows up on the finance server, being used for remote service installation. Installing a service remotely is one of the standard ways to get code running on another host. And the target is the file server holding the data the attacker went on to stage and exfiltrate, so this also links the credential to the next stage of the chain.

Three independent sources, three different parts of the attack, one account. Running the same search for the other nine candidates does not produce this pattern. The ordinary service accounts show up doing ordinary local work and nothing else.

So the attacker dumped ten credentials from `SRV-WEB01` and chose `svc_backup`. From their point of view that makes sense. A backup account normally has broad read access across file servers, and its activity is noisy by nature, so it blends in much better than a named administrator account would.

### Flag

The dump gives the password for that account, and the authentication logs prove it is the one that was reused.

- username: `svc_backup`
- password: `B4ckup!2026`

```text
FLAG{svc_backup:B4ckup!2026}
```

### The fix

The breach needed two separate failures, and both are fixable.

**The credentials should not have been readable in clear text.** The dump shows real passwords under `wdigest`, which means WDigest credential caching was still enabled on `SRV-WEB01`. Microsoft turned this off by default years ago, and it can be forced off by setting `UseLogonCredential` to `0` under `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`. With that off the attacker would have got hashes instead of passwords, which is a much slower road.

**One stolen account should not have reached the finance server.** `svc_backup` was dumped from a web server and then used to install a service on `SRV-FIN01`. A backup account needs read access to the data it backs up, not the right to create services on other machines. Tiering administrative accounts, and denying service accounts network logon where they do not need it, breaks the step between the web server and the finance server.

The detection side is worth saying too. The account authenticating through the VPN from an external address was by itself enough to open an investigation. Service accounts run locally under the service control manager and never dial in, so a VPN login for one is always worth an alert.

---

[Back to this event](README.md) · [All writeups](../README.md)
