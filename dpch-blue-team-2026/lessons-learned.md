# What I learned

These are the mistakes that actually cost time during these five solves. They are written down because every one of them will happen again otherwise.

### Read the flag format before you touch the evidence

On the two easiest challenges the format was the most useful information available, and it was free.

Plainwire asks for `FLAG{username:password}`. That rules out six of the seven intrusion stages in the brief, and it rules out hashes, so the answer has to come from credential dumping in clear text. One `find` command later I was looking at the right file.

Breachmaster asks for the password on its own. Put that next to `wdigest` showing `(null)` in the dump, and the route is decided before any tool runs. No clear text exists, so the NTLM hash is the only way through.

**The format tells you which stage of the attack the answer lives in.** Work that out first and most of the evidence stops being relevant.

### A high value flag can hold more than one value

Antiobook cost me five rejected submissions. I had decoded the implant config, broken the stage-2 encryption and recovered the OAuth client id, and the Entra audit note said in plain English that the client id was recoverable only from the implant. I submitted it. Wrong. I submitted the campaign code, the config digest, the dead drop mailbox and the operator domain. All wrong.

Every one of those values was correct. The flag wanted two of them joined with an underscore:

```text
flag{<campaign_code>_<oauth_client_id>}
```

The challenge page gave no format at all, and another high value challenge in the same event was built the same way, so this was the setter's habit rather than a one off.

**When a value you can prove from several independent sources gets rejected, stop looking for a different value.** Start joining the pivot points of the chain you have already reconstructed.

### Two indicators can come from two different layers

Apartment asked for the C2 domain and the implant's file identity. I read "blocklist" as meaning network things, so I paired the domain with the C2 IP address. Twice, in both orders. Both wrong.

A blocklist is not only firewall rules. It also covers file hashes pushed to the endpoint agent. One indicator was network and one was host, which is also how it works on a real job.

**Check whether the two halves of a flag are meant to come from the same place before you assume they are.**

### Judge files by behaviour, never by name

This came up in three of the five.

RedBulb had 3,431 extracted HTTP objects, dozens of them starting with `MZ` and holding nothing but random bytes, plus a `.pdf.exe` double extension download sitting there asking to be picked. The actual malware was named `Wextract.exe` and looked less suspicious than the decoy.

Apartment had two different files both called `TenantUpdate.exe`, with different hashes, on two different hosts. The only thing that separated them was which process wrote each one. `chrome.exe` into Downloads is a user downloading something. `powershell.exe` into Temp, run one second later, is a payload being staged.

Breachmaster had four accounts and `Administrator` was not the answer.

**Ask who served it, what sent the user there, and what the machine did next.** The third question is the strongest one, because a normal installer finishes and nothing follows, while malware that runs reaches for its control server.

### Count instead of reading

The DNS log in Apartment is 2.2 MB. I did not read it. `grep -c` on the suspicious name returned `1`.

A real service is queried hundreds of times a day as caches expire. A name asked for once in a whole day is not a service anybody uses, it is one program calling home one time.

**In a big log, the rarest entry is usually more interesting than the most common one.** Beacons are loud. First stage lookups are quiet.

### Reserved address ranges mean the host is scenery

RedBulb's `.pdf.exe` decoy resolved to `198.51.100.88`. That block is TEST-NET-2, reserved by the RFCs for documentation and examples, so nothing can actually be hosted there. The real delivery server was in ordinary routable space.

`192.0.2.0/24`, `198.51.100.0/24` and `203.0.113.0/24` are all reserved the same way.

**When a suspicious host in an exercise resolves into one of those ranges, it is decoration.**

### Check a carved file is complete before you hash it

RedBulb's flag is a SHA-256. A hash of a half carved download is wrong and still looks perfectly valid, which makes it invisible.

Comparing `http.content_length` from the response against the size on disk takes one command, and parsing the PE header confirms it is a real executable rather than another fake `MZ` blob.

**Verify the artifact before you compute anything from it.** There is no error message for hashing the wrong bytes.

### Obfuscation details that cost an hour each

Two from Antiobook, both the kind of thing that makes you believe your key is wrong when it is not.

**Alternating XOR has two phases.** The strings export said "XOR 0xAB/0xCD", but it does not say whether the blob starts on the `0xAB` byte or the `0xCD` byte. Get it backwards and the output is garbage that looks exactly like a wrong key. Testing both is one extra loop.

**A custom base64 alphabet fails quietly.** The stage-2 loader ships its own 64 character alphabet. The encoded RC4 key decodes happily under the standard table and hands back a wrong 16 byte key with no error at all. When a loader carries its own alphabet, use it for everything in that loader, the key material included.

### Verify what a third party tool tells you

Breachmaster's hash came back from an online lookup service in under a second. That is a convenience, not evidence.

NTLM is `MD4(password as UTF-16LE)` with no salt, so recomputing the hash from the returned password takes three lines of Python. It matched. If it had not, I would have been submitting somebody else's answer.

**A lookup is a claim until you reproduce it yourself.**
