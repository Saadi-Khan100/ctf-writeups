# RedBulb

## Understanding the challenge

|  |  |
| --- | --- |
| Category | Blue Team / Network Forensics |
| Event | DPCH Online Qualifiers (Cydea Range platform) |
| Team | Pwnag3 |
| Files given | `redbulb.pcap` (50 MB packet capture) |
| Flag format | `flag{<64 lowercase hexadecimal SHA-256>}` |

### What the challenge says

A user on the network downloaded a malicious program and ran it. I have a full packet capture of that day. I have to pull the malicious file back out of the traffic and give its SHA-256 hash.

### What the flag format tells me

The flag is one SHA-256 hash. Nothing else. So the whole challenge comes down to a single decision. Which file in this capture is the malware?

Once I pick the right file, getting the hash is one command. So all the real work is in picking correctly. And a capture built for this kind of challenge will be full of files that are not the answer.

### My plan

A 50 MB capture is too big to scroll through, so I made a plan first.

1. Find out which protocols are inside it, so I know where files could be hiding.
2. Pull out every file that went over HTTP.
3. Cut that list down to programs only.
4. For each program, use the traffic around it to decide if it was a real download from a real vendor, or a delivery from an attacker.
5. Hash the one that is left.

## Step 1: seeing what is inside the capture

```bash
tshark -r redbulb.pcap -q -z io,phs
```

What the options do:

- `-r` reads from a file instead of a live network interface.
- `-z io,phs` prints the protocol hierarchy statistics. It gives me a tree of every protocol in the capture with frame and byte counts.
- `-q` means quiet. tshark then prints only the statistics at the end, instead of dumping every packet to my screen.

This is always my first command on a capture I have not seen before. It tells me in one go whether I am dealing with HTTP, TLS, SMB, DNS or something unusual. It saves me from guessing.

Output:

```text
eth                                      frames:70912 bytes:51294184
  ip                                     frames:70272 bytes:51267304
    udp                                  frames:2976 bytes:279718
      dhcp                               frames:16 bytes:5010
      dns                                frames:2780 bytes:257788
      ntp                                frames:180 bytes:16920
    tcp                                  frames:67206 bytes:50980926
      http                               frames:7976 bytes:11011224
        json                             frames:433 bytes:173864
        data-text-lines                  frames:204 bytes:237376
        png                              frames:36 bytes:10180
        data                             frames:27 bytes:21080
        media                            frames:4 bytes:2017
        mime_multipart                   frames:5 bytes:5642
      smtp                               frames:234 bytes:24619
        imf                              frames:18 bytes:4315
      tls                                frames:1311 bytes:1092392
```

This is good news. There are 7,976 HTTP frames carrying 11 MB, and only 1,311 TLS frames. So the file transfer happened over plain HTTP and not over HTTPS. I can read it without needing any keys. There is also DNS, which turned out to matter a lot later, and a small amount of SMTP.

## Step 2: pulling every file out of the HTTP traffic

```bash
mkdir -p objs
tshark -r redbulb.pcap --export-objects http,objs >/dev/null 2>&1
ls objs | wc -l
```

`--export-objects http,objs` tells tshark to rebuild every file that was sent over HTTP and write it into the `objs` folder. tshark does the hard part for me here. A file arrives split across many TCP packets, and this option puts the pieces back together in the right order.

I send the normal output to `/dev/null` because I only care about the files landing on disk. I do not need the packet summary.

Output:

```text
3431
```

3,431 files. This is the trap in this challenge. Most of them are web pages, small PNG images, JSON replies from APIs, and padding. A lot of them are named `%2f`, which is just the URL encoded form of `/`, so those are requests for a site root. Opening 3,431 files one by one is not an option.

I looked at a few to see what kind of noise I was dealing with.

```bash
head -c 120 'objs/%2f'
head -c 60 'objs/%2f(4)'
head -c 40 'objs/%2f(13)'
```

```text
<!doctype html><html><head><meta charset="utf-8"><title>Www</title></head><body><h1>Www</h1>
MZ+:...<random bytes>...
.PNG....IHDR....
```

Look at the second one. It starts with `MZ`, which is the magic signature at the start of every Windows executable. But the rest of it is random bytes. The capture is full of fake executables that only have the correct first two letters.

So "starts with MZ" is not enough to call something a program. Anyone who filters only on `MZ` will end up with dozens of candidates and no way to choose between them.

## Step 3: cutting down to real program downloads

Instead of judging the extracted files, I went back to the capture and asked a different question. What was actually requested? A malware delivery is a request for a program file.

```bash
tshark -r redbulb.pcap -Y 'http.request' -T fields -e http.host -e http.request.uri \
  | grep -iE '\.exe|\.msi|\.dll|\.ps1|\.hta' | sort -u
```

What the options do:

- `-Y 'http.request'` is a display filter. It keeps only request packets. So I get one line per thing the user asked for, instead of requests and responses mixed together.
- `-T fields -e http.host -e http.request.uri` prints only the two columns I want, separated by a tab, instead of a human readable summary. This is the part that makes the output easy to pipe into `grep`.
- The `grep -iE` pattern keeps only the file types that can run on Windows. `-i` for case, and `-E` so that `|` works as "or".

Output:

```text
cdn.wextract-updates.com	/dl/9f3c1a7e/Wextract.exe
cdn.zoom.us	/prod/4.8.10.2645/ZoomInstallerFull.exe
dl.google.com	/chrome/install/GoogleChromeStandaloneEnterprise64.msi
download.microsoft.com	/download/4/2/1/OfficeSetup.exe
files.invoice-portal.com	/download/Invoice_Nov2026.pdf.exe
updates.adobe.com	/pub/adobe/reader/win/AcrobatUpdate.exe
```

From 3,431 files down to six candidates. Now I have a question I can actually answer.

Four of them look like normal software from vendors I know. Zoom, Google Chrome, Microsoft Office, Adobe Reader. Two of them look suspicious.

`files.invoice-portal.com/download/Invoice_Nov2026.pdf.exe` has a double extension. The user sees "Invoice_Nov2026.pdf" and the real file type is `.exe`. This is the oldest phishing trick there is, and it looks like the most obvious answer.

`cdn.wextract-updates.com/dl/9f3c1a7e/Wextract.exe` comes from a vendor name I do not recognise, and the path has a random looking folder called `9f3c1a7e`.

My first instinct was the `.pdf.exe` one. That instinct was wrong. The rest of this writeup is how I proved which one is which instead of guessing.

## Step 4: deciding which download was the attack

A file name proves nothing. What proves something is the traffic around the download. For each candidate I looked at three things. Who served it, what sent the user there, and what the machine did afterwards.

### Who served it

```bash
tshark -r redbulb.pcap -Y 'dns.flags.response==1' -T fields -e dns.qry.name -e dns.a \
  | grep -iE 'wextract|invoice-portal|adobe|zoom|dl.google|download.microsoft' | sort -u
```

`dns.flags.response==1` keeps only DNS replies. The question packets have no answer inside them, so there is no point including them. `-e dns.a` prints the A record, which is the IP address the name resolved to.

Output:

```text
cdn.wextract-updates.com	45.155.205.233
files.invoice-portal.com	198.51.100.88
updates.adobe.com	193.104.215.14
dl.google.com	142.250.190.78
cdn.zoom.us	170.114.52.2
download.microsoft.com	23.45.78.100
```

`198.51.100.88` stands out, but not the way I expected it to. The range `198.51.100.0/24` is called TEST-NET-2. The RFCs reserve it for documentation and examples. No real attacker server lives there. It is the kind of address you use when you are writing a manual, or building a fake lead.

So the scary looking `.pdf.exe` download points at an address that cannot host anything at all.

`45.155.205.233` is in ordinary routable address space, the kind that cheap hosting providers use. That is where a real delivery server would sit.

### What sent the user there

```bash
tshark -r redbulb.pcap -Y 'http.request' \
  -T fields -e http.host -e http.request.uri -e http.referer -e http.user_agent \
  | grep -iE '\.exe|\.msi'
```

Adding `-e http.referer` is the important part here. The Referer header says which page the browser was on when it asked for this file. A download with no referer was started by a program, like an auto updater. A download with a referer came from a user clicking a link on a page.

Output, cut down to the columns that matter:

```text
dl.google.com      /chrome/install/...msi            (no referer)  Firefox/128.0
updates.adobe.com  /pub/adobe/reader/win/...exe      (no referer)  Microsoft BITS/7.8
download.microsoft.com /download/4/2/1/OfficeSetup.exe (no referer) Microsoft-CryptoAPI/10.0
cdn.zoom.us        /prod/4.8.10.2645/...exe          (no referer)  Chrome/126 Edg/126
files.invoice-portal.com /download/Invoice_Nov2026.pdf.exe (no referer) Chrome/126 Edg/126
cdn.wextract-updates.com /dl/9f3c1a7e/Wextract.exe   http://cdn.wextract-updates.com/invoice/nov-2026   Chrome/126
```

Only one download has a referer, and it is the Wextract one. The user was on a page called `/invoice/nov-2026`, hosted on the attacker's own server, and from that page they were sent to the program. A landing page leading to a payload is exactly what a real delivery chain looks like.

The Adobe and Microsoft downloads have `Microsoft BITS/7.8` and `Microsoft-CryptoAPI/10.0` as their user agent. Those are Windows background update services, not a browser. So that is normal machine behaviour and not a person clicking anything.

### What the machine did afterwards

This is the check that settled it for me. Malware that runs calls home. So I looked at DNS around the time of each download.

```bash
tshark -r redbulb.pcap -Y 'dns' \
  -T fields -e frame.time -e dns.flags.response -e dns.qry.name -e dns.a \
  | grep -i wextract
```

Output:

```text
Nov  2, 2026 14:14:02.000000000   False  cdn.wextract-updates.com
Nov  2, 2026 14:14:02.013301000   True   cdn.wextract-updates.com   45.155.205.233
Nov  2, 2026 14:14:20.000000000   False  api.wextract-sync.com
Nov  2, 2026 14:14:20.019153000   True   api.wextract-sync.com
```

Reading the timeline:

At `14:14:02` the machine resolves `cdn.wextract-updates.com` and downloads `Wextract.exe`.

At `14:14:20`, eighteen seconds later, the machine asks DNS for `api.wextract-sync.com`.

That second name is a different domain, but it belongs to the same family. `wextract-updates` delivered the file, and `wextract-sync` is where the file reports back to. Nobody types a name like that into a browser. A program on the machine asked for it. And the only new program on that machine was the file that had just landed.

The reply has no address in it, so the name did not resolve and no HTTP followed. That does not weaken the evidence. It actually fills in the story. The implant ran, tried to reach its control server, and failed. The failed lookup still proves the file executed.

I ran the same check on the other five downloads. None of them is followed by a lookup of some unrelated attacker style domain. Chrome talks to Google. Zoom talks to Zoom.

So my decision was:

| Download | Verdict | Why |
| --- | --- | --- |
| `GoogleChromeStandaloneEnterprise64.msi` | benign | real Google IP, no referer, normal browser |
| `AcrobatUpdate.exe` | benign | fetched by BITS, the Windows updater |
| `OfficeSetup.exe` | benign | fetched by CryptoAPI |
| `ZoomInstallerFull.exe` | benign | real Zoom IP |
| `Invoice_Nov2026.pdf.exe` | fake lead | scary name, but served from documentation address space, and nothing happens after it |
| `Wextract.exe` | malware | attacker host, landing page referer, and a C2 lookup 18 seconds later |

## Step 5: checking the extracted file is complete

Before hashing anything I had to be sure the file tshark rebuilt is the whole file. A hash of a half downloaded file is a wrong hash that still looks perfectly valid. That mistake is invisible, so I always check.

```bash
tshark -r redbulb.pcap -Y 'http.response && http.content_length' \
  -T fields -e http.content_length -e http.content_type -e http.response_for.uri \
  | grep -i wextract
```

`http.content_length` is the size the server said it was going to send. `http.response_for.uri` links the response back to the request it answers. I need that field because responses do not carry the URL themselves.

Output:

```text
187392	application/octet-stream	http://cdn.wextract-updates.com/dl/9f3c1a7e/Wextract.exe
```

```bash
ls -l objs/Wextract.exe
```

```text
-rw-r--r-- 1 root root 187392 objs/Wextract.exe
```

187392 bytes promised, 187392 bytes on disk. Nothing is missing.

Then I checked that it is a real Windows program and not another fake `MZ` blob.

```bash
python3 -c "
import struct
d = open('objs/Wextract.exe','rb').read()
print('DOS magic :', d[:2])
pe = struct.unpack('<I', d[0x3c:0x40])[0]
print('e_lfanew  :', hex(pe))
print('PE magic  :', d[pe:pe+4])
print('size      :', len(d))
"
```

Here is how a PE file is laid out, and why these three checks are enough.

Bytes 0 and 1 are `MZ`. Every Windows executable starts with this. The fake objects in this capture also have it, so on its own it means nothing.

The four bytes at offset `0x3c` hold a value called `e_lfanew`. It is a pointer to where the real PE header starts. `struct.unpack('<I', ...)` reads those four bytes as a little endian unsigned 32 bit integer, because that is how Windows stores them.

At that offset there must be `PE\0\0`. A random blob is not going to have a valid pointer that happens to land on a valid signature. If this check passes, the file is a real executable.

Output:

```text
DOS magic : b'MZ'
e_lfanew  : 0x80
PE magic  : b'PE\x00\x00'
size      : 187392
```

A real PE file, and complete.

### Flag

```bash
sha256sum objs/Wextract.exe
```

Output:

```text
abacd643399cbc6b1a56c26ce049cb72f84041da113f80ac9634c3b3e48d69d2  objs/Wextract.exe
```

The format asks for 64 lowercase hex characters. `sha256sum` already prints lowercase, so this goes in as it is.

```text
flag{abacd643399cbc6b1a56c26ce049cb72f84041da113f80ac9634c3b3e48d69d2}
```

Accepted on the first try.

### The fix

The delivery worked because a user could fetch and run a program straight from an unknown host over plain HTTP, and nothing on the network stopped it.

**Executables should not arrive over plain HTTP from uncategorised domains.** A web proxy that blocks `application/octet-stream` downloads from newly registered or uncategorised domains would have stopped this at `14:14:02`. The traffic was unencrypted, so the proxy could see exactly what was being transferred.

**The failed C2 lookup was free detection.** Eighteen seconds after the download, the host asked DNS for `api.wextract-sync.com` and got nothing back. A host resolving a name that does not exist, right after downloading a program from a sibling domain, is a strong signal. Alerting on NXDOMAIN responses for newly seen names catches this even when the C2 never answers.

**Application control would have ended it regardless.** The payload ran from a user writable path. WDAC or AppLocker in a configuration that only permits execution from `Program Files` and `Windows` stops a download in the user profile from running at all, whatever the user clicks.

---

[Back to this event](README.md) · [All writeups](../README.md)
