# Antiobook

## Understanding the challenge

|  |  |
| --- | --- |
| Category | Blue Team / Malware Analysis and Intrusion Reconstruction |
| Event | DPCH Online Qualifiers (Cydea Range platform) |
| Team | Pwnag3 |
| Files given | `artifacts.tgz` (phishing emails, stagers, stage-2 payloads, implant binaries, endpoint telemetry, memory dumps, M365 audit, network logs) |

### What the challenge says

> One Tuesday morning, in ninety-one silent seconds, a researcher's laptop stopped being hers. No alert fired, no dialog opened, and every scan since has come back disturbingly clean. The record of that morning is still inside the machine, inert, waiting for someone like you.

The challenge page gave no flag format. That mattered a lot later.

### Pulling the description apart

Every part of that paragraph is a pointer. So I read it as instructions and not as decoration.

**"a researcher's laptop"** is singular, and it says researcher, not a finance or IT user. The evidence has three hosts, so this tells me which one to focus on.

**"ninety-one silent seconds"** means there is a 91 second window somewhere in the timestamps, and the whole compromise fits inside it.

**"No alert fired, no dialog opened"** means there was no UAC prompt, so no privilege escalation. Everything runs as the user. And nothing got blocked, so the tools used are all signed or already built into Windows.

**"every scan since has come back disturbingly clean"** means the implant is not a file an antivirus can detect. Either it is encrypted on disk, or it only exists properly in memory.

**"The record of that morning is still inside the machine, inert"** means the configuration is sitting in a memory dump, encoded, not running. The word "inert" is what told me to go to the memory dump and decode something, rather than go looking for live network traffic.

So before running a single command I expected one host, a 91 second window, an execution chain made of signed binaries, and an encoded config inside a memory dump.

## Opening the evidence

```bash
mkdir -p ~/antiobook/ev && cd ~/antiobook/ev
tar xzf '../artifacts (15).tgz'
find . -type f -printf '%10s  %P\n' | sort -k2
```

The folders are numbered by attack phase, which made this much easier to work through:

```text
evidence/01_email/              phishing emails and mail gateway log
evidence/02_documents/          the decoy PDFs
evidence/03_delivery/           .hta and .wsf stagers, Cloudflare Pages access log
evidence/04_stage2/             the encrypted stage-2 payloads and the loader
evidence/05_implant/            the implant DLLs, host binaries, installer
evidence/06_endpoint/           EDR, registry and PowerShell logs for 3 hosts
evidence/07_memory/             3 process memory dumps, 256 KB each
evidence/08_m365/               Entra audit, Graph API activity, dead-drop listing
evidence/09_network/            DNS, firewall, proxy
```

Three hosts show up everywhere. `IN-WS-7731`, `PH-FIN-2208` and `WIN-TWWS4417`.

Picking the researcher's laptop took one look. `WIN-TWWS4417` has `TW` in its name, and there is a folder called `03_delivery/stagers/tpie/` plus a document called `Taiwan_Information_Warfare_Workshop.pdf`. So that host is tied to a Taiwan themed lure. `PH-FIN-2208` has `FIN` in it, so that is finance. `IN-WS-7731` got infected days later through a fake Flash installer, which is a separate delivery.

So I went with `WIN-TWWS4417`. The username on that host turned out to be `jwu`.

## Step 1: building the 91 second timeline

I started on the host side, because process and file events give the clearest order of what happened.

```bash
cd evidence/06_endpoint/WIN-TWWS4417
cat edr_process_events.csv
```

These exports are only a couple of kilobytes each, so reading them whole is faster than writing filters. I only reach for `grep` when a file is too big to read.

The process events, cut down to the columns that matter:

```text
09:43:18  mshta.exe          parent OUTLOOK.EXE   "mshta.exe C:\Users\jwu\AppData\Local\Temp/CSIS_Indo-Pacific_Forecast_2026.hta"
09:43:31  GatherOsState.exe  parent mshta.exe     C:\Users\jwu\AppData\Local\Temp/HeiqAW6Z/GatherOsState.exe
09:43:52  sdiagnhost.exe     parent mshta.exe     %windir%\SysWOW64\sdiagnhost.exe -Embedding
09:43:53  powershell.exe     parent sdiagnhost    -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Windows\Temp\SDIAG_8f3c1a56-...\result.ps1
10:03:18  cmd.exe            parent sdiagnhost    cmd.exe /C whoami /all & net group "Domain Admins" /domain
```

Every single process in that list is signed by Microsoft. `mshta.exe`, `GatherOsState.exe`, `sdiagnhost.exe`, `powershell.exe` and `cmd.exe`. This is the "no alert fired" part of the description. An antivirus product looking for unsigned binaries sees nothing here at all.

`mshta.exe` with `OUTLOOK.EXE` as the parent is the opening move. The user opened an attachment from Outlook, and that attachment was an `.hta` file. Windows runs `.hta` files as scripts with full scripting access.

Then the file events:

```bash
cat edr_file_events.csv
```

```text
09:41:44  FileCreate  C:\Users\jwu\AppData\Local\Temp/CSIS_Indo-Pacific_Forecast_2026.hta   by OUTLOOK.EXE   unsigned
09:43:30  FileOpen    C:\Users\jwu\AppData\Local\Temp/HeiqAW6ZEventDetails.pdf              by mshta.exe
09:43:33  FileCreate  .../HeiqAW6Z/HeiqAW6ZGatherOsState.exe.luy   by mshta.exe   valid (Microsoft Corporation)
09:43:33  FileCreate  .../HeiqAW6Z/HeiqAW6Zslc.dll.pzs             by mshta.exe   unsigned
09:43:33  FileCreate  .../HeiqAW6Z/HeiqAW6ZOsGather.dat.syk        by mshta.exe   unsigned
09:44:06  FileCreate  C:\Users\jwu\AppData\Local\Windows GatherOSStateKit\GatherOsState.exe  by GatherOsState.exe
```

Two details here.

The downloaded files have junk extensions. `.luy`, `.pzs`, `.syk`. The EDR even labels this as "create (written with randomized extension)". Downloading `slc.dll` directly might set off a rule about DLLs landing in Temp, so it arrives as `.pzs` and gets renamed before use.

The decoy PDF opens at `09:43:30`, which is one second before the implant host binary starts. That PDF is the only thing `jwu` ever saw. She clicked an attachment, a PDF about an Indo-Pacific forecast appeared, and she read it while everything else happened underneath.

Then the module loads, which is where it gets interesting:

```bash
cat edr_module_load_events.csv
```

```text
09:43:35  GatherOsState.exe  loads  slc.dll        from the same directory   method: sideload   export_called: SLOpen
09:43:36  GatherOsState.exe  loads  sdiageng.dll   from System32             method: COM activation (CLSID {1F3D8AA5-9EBF-4EE4-85C2-EA40379AEDE8})
```

This is DLL side loading. `GatherOsState.exe` is a real signed Microsoft binary that normally ships with Windows upgrade tooling, and it genuinely imports `slc.dll`. Windows looks for a DLL in the executable's own folder before it looks in System32.

So the attacker copies the signed `GatherOsState.exe` into a folder they control, drops their own `slc.dll` next to it, and runs the signed binary. Windows then loads the malicious DLL into a trusted signed process. The export called is `SLOpen`, which is a real function name in the genuine `slc.dll`, so the fake one has to implement it to keep the host program happy.

The registry and PowerShell logs finish the picture:

```bash
cat registry_audit.csv
cat powershell_scriptblock_4104.csv
```

```text
09:43:53  SetValue  HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
          GatherOsState = "%LOCALAPPDATA%\Windows GatherOSStateKit\GatherOsState.exe"   by powershell.exe
```

The persistence goes under `HKCU` and not `HKLM`. `HKCU` is the current user's own hive, and writing to it needs no administrator rights. So no UAC dialog appeared, which matches the description. The install folder is called `Windows GatherOSStateKit`, picked so it looks like a Microsoft component in a list of startup entries.

Now the network side, to find the actual 91 seconds:

```bash
cd ../../09_network
cat dns_queries.log
cat proxy_access.log
```

```text
09:41:48  10.44.18.77  my-662ylt3w.pages.dev                           A  104.21.63.18
09:43:18  10.44.18.77  pub-abfa7742e315485a98a5fafd6dbfb68e.r2.dev     A  104.21.63.18
09:43:19  10.44.18.77  oisadjfoinsiduhfnoisdnfosdnoifnsoid.pages.dev   A  104.21.63.18
09:45:00  10.44.18.77  login.microsoftonline.com                       A  20.190.159.4
09:45:04  10.44.18.77  graph.microsoft.com                             CNAME 20.190.159.11
```

From `09:41:48` to `09:43:19` is exactly 91 seconds. First lookup to last lookup of attacker infrastructure. That is the window from the description, and it confirmed I was on the right host.

The hosting choice is worth a note. `pages.dev` and `r2.dev` are Cloudflare Pages and Cloudflare R2. Both resolve to `104.21.63.18`, which is a Cloudflare address. A company cannot block that IP, because a large part of the internet sits behind it. So the attacker is hiding inside infrastructure that cannot be blocked as a whole.

Here is the full timeline:

```text
09:41:44  Outlook writes CSIS_Indo-Pacific_Forecast_2026.hta to Temp
09:41:48  DNS my-662ylt3w.pages.dev                        <-- window starts
09:41:49  GET /File_download?m=TW-MIISS-0043
09:43:18  mshta.exe runs the .hta, fetches /Qw7Womin4X6N   (stage-2 loader)
09:43:19  DNS oisadjfoinsiduhfnoisdnfosdnoifnsoid.pages.dev <-- window ends, 91s
09:43:24  fetch HzjNPgRE9ir92e38.txt                        (encrypted gadget blob)
09:43:30  decoy PDF opens                                   <-- all the user saw
09:43:31  GatherOsState.exe starts
09:43:33  slc.dll.pzs and OsGather.dat.syk written beside it
09:43:35  slc.dll side-loaded through export SLOpen          <-- implant is live
09:43:52  sdiagnhost.exe via COM CLSID {1F3D8AA5-...}
09:43:53  powershell writes the HKCU Run key
09:44:06  self-install to %LOCALAPPDATA%\Windows GatherOSStateKit\
09:45:00+ Graph and OneDrive dead-drop C2
```

## Step 2: the inert record in the memory dump

The description said the record is inside the machine and inert. So I went to the memory dump for that host.

```bash
cd ../07_memory/WIN-TWWS4417
ls -l
cat strings_GatherOsState_dump.txt
```

The strings export that came with the dump is only 1.3 KB, and it gives away the implant's whole vocabulary:

```text
ANTINO-IMPLANT-STRINGTABLE
VirtualAlloc / VirtualProtect / AddVectoredExceptionHandler / FlushInstructionCache
system_info  execute_program  list_files  upload_file  download_file  load_shellcode  add_to_run
ANTINO-CFG-IMAGE (encoded at rest, XOR 0xAB/0xCD)
ANTINO-SLEEP-MASK-REGION  (PAGE_READWRITE, XOR-obfuscated while sleeping)
VEH-HANDLER-INSTALLED
```

So the implant is called **Antino**, and its command set is a normal remote access toolkit.

One line is basically an instruction to me. The config image is encoded at rest with XOR 0xAB/0xCD. Not one XOR byte, two of them, which means they alternate.

Instead of hunting for offsets by hand, I let the dump tell me where its data is. A 256 KB dump is mostly zeros, so the real content sits in runs of non-zero bytes.

```bash
python3 - <<'EOF'
d = open('memdump_GatherOsState_pid4821_0x00008009770c0000.bin','rb').read()

# walk the dump and collect every run of non-zero bytes of useful length
runs = []
i = 0
while i < len(d):
    if d[i]:
        j = i
        while j < len(d) and d[j]:
            j += 1
        if j - i >= 48:
            runs.append((i, j))
        i = j
    else:
        i += 1

# for each run, try both phases of the alternating XOR and keep what turns into text
for a, b in runs:
    blob = d[a:b]
    for phase in (0, 1):
        key = bytes([0xAB, 0xCD][(n + phase) % 2] for n in range(len(blob)))
        out = bytes(x ^ y for x, y in zip(blob, key))
        printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in out)
        if printable > len(out) * 0.9:
            print(f"=== offset {hex(a)} len {b-a} phase {phase} ===")
            print(out.decode('utf8', 'replace'))
EOF
```

Why I built the script this way:

Walking the non-zero runs means I never have to guess an offset. Whatever the layout is, the data finds me.

The `>= 48` check throws out single stray bytes. A config is hundreds of bytes long.

Trying both phases is the part that really matters. "XOR 0xAB/0xCD" alternates per byte, but I do not know whether the blob starts on the `0xAB` byte or on the `0xCD` byte. If I get it backwards the output is garbage, and garbage looks exactly the same as a wrong key. Testing both costs me one extra loop and takes the guesswork away.

The 90 percent printable test is how the script decides it worked, so I do not have to read hex myself.

Output:

```text
=== offset 0x7e5 len 49 phase 0 ===
ANTINO-CFG-IMAGE (encoded at rest, XOR 0xAB/0xCD)

=== offset 0x81b len 554 phase 0 ===
{"implant":"antino","version":"2","campaign_code":"TW0626-A7F3",
 "tenant_id":"7c1a9d40-5b62-4e88-9a13-2d6f0c8e4b57",
 "mailbox":"md-archive@outlook.com",
 "drive_id":"b!4e9c17a2f5d84c6ba07c3e19d2f8b645",
 "heartbeat_path":"/antino/heartbeats/{session_id}.json",
 "command_subject_prefix":"command_req_","response_subject_prefix":"command_res_",
 "poll_seconds":10,"heartbeat_seconds":60,
 "oauth_flow":"client_credentials","secret_ref":"ref-7f3a91c4",
 "run":true,"launch_mode":"dll",
 "install_dir":"%LOCALAPPDATA%\\Windows GatherOSStateKit",
 "run_value":"GatherOsState"}
```

The whole configuration, in clear text.

And now the C2 design makes sense. There is no attacker server at all. The implant signs in to Microsoft with OAuth and uses a normal Outlook mailbox as a dead drop. Commands arrive as emails with subjects starting `command_req_`. Answers go back as `command_res_`. Heartbeats get written as JSON files into OneDrive. All the traffic goes to `graph.microsoft.com` and `login.microsoftonline.com`, which no company can block.

I also decoded the same config straight out of the implant DLL on disk, to show it is stored encoded there too:

```bash
cd ../../05_implant
python3 - <<'EOF'
import re
for p in ['csis/HeiqAW6Zslc.dll.pzs', 'tpie/bzP3NcRPslc.dll.czh',
          'installer/flashcenter_pp_ax_install_en.exe']:
    d = open(p, 'rb').read()
    i = 0
    while i < len(d):
        if d[i]:
            j = i
            while j < len(d) and d[j]:
                j += 1
            if j - i >= 64:
                blob = d[i:j]
                for ph in (0, 1):
                    k = bytes([0xAB, 0xCD][(n + ph) % 2] for n in range(len(blob)))
                    out = bytes(x ^ y for x, y in zip(blob, k))
                    if b'implant' in out:
                        print(p, '->', out.decode('utf8', 'replace')[:120], '...')
            i = j
        else:
            i += 1
EOF
```

```text
csis/HeiqAW6Zslc.dll.pzs       -> {"implant":"antino","version":"2","campaign_code":"TW0626-A7F3", ...
tpie/bzP3NcRPslc.dll.czh       -> {"implant":"antino","version":"1","campaign_code":"PH0626-4B19", ...
installer/flashcenter_...exe   -> {"implant":"antino","version":"2","campaign_code":"IN0626-51C7", ...
```

Three campaigns, one for each host. `TW0626-A7F3` for the Taiwan researcher, `PH0626-4B19` for the Philippines finance host, and `IN0626-51C7` for the fake Flash installer. The `campaign_code` is how the operator tells victims apart, and it is different for each victim.

This is also where I hit a wall. None of these configs has an OAuth client id in it. They have the tenant id and a `secret_ref`, but no client id. That gap is on purpose, and working out why was the rest of the challenge.

## Step 3: what the challenge is actually asking for

I had plenty of values and no idea which one was wanted. So I went looking for the question itself. It was in the M365 folder.

```bash
cd ../08_m365
cat entra_service_principal_audit.txt
```

```text
resource: /a/0c9d1f0a-4e9c-17a2-f5d8-4c6ba07c3e19
Service principal display name : Antino Dead-Drop Client
Application (client) ID        : <NOT RECOVERED - see note>
Object ID                      : <NOT RECOVERED>
Created                        : 2026-05-27T04:11:52Z
Deleted                        : 2026-06-14T02:12:44Z   (deleted by principal owner)
Credentials                    : 1 client secret, last rotated 2026-05-27T04:12:30Z
Redirect URIs                  : https://localhost/

NOTE (IR lead, 2026-06-26): the service principal above was deleted by the
actor during cleanup. The unified audit log retains only the display name and
the deleted object id. The application (client) ID is therefore recoverable
ONLY from the implant itself.
```

There it is, written out in plain English. The attacker deleted their Entra application during cleanup, so the cloud logs no longer have its client id. The only remaining copy is inside the implant.

The Graph API export says the same thing a second time. "this sensor logs the token's application name only, the application (client) id is not exported."

So the objective is the OAuth application (client) ID. And I had just confirmed it is not in the config blob I decoded. It had to be somewhere in the delivery chain.

## Step 4: breaking the stage-2 encryption

The stage-2 folder has the loader and three encrypted resources.

```bash
cd ../04_stage2/csis
ls -l
head -c 1200 Qw7Womin4X6N
```

`Qw7Womin4X6N` is the loader that `mshta.exe` fetched at `09:43:18`, and it is plain JavaScript. It gives me both halves of the crypto:

```javascript
// Antino stage-2 loader -- executed in-process by mshta.exe
var _alphabet = "qYPwzs07b9MUeLZcrHEhyWGt/OX35IaSAxJp2Qv6Rjf1oNuB+4FdClD8KinVTkgm";
var _k64      = "LD/d/h24/dHJZ0y+LGrFLA==";
var _res      = [
  "https://pub-abfa.../0u25lAqY58or53ra.js",
  "https://pub-abfa.../gpv0IRMtvto6e8t2.txt",
  "https://pub-abfa.../HzjNPgRE9ir92e38.txt"
];
```

There are two layers, and the second one has a catch.

**Layer one is base64 with a custom alphabet.** Standard base64 maps value 0 to `A`, 1 to `B` and so on. This one maps 0 to `q`, 1 to `Y`, 2 to `P`. The data still looks like ordinary base64, so any tool that tries standard base64 produces garbage that looks plausible instead of throwing an obvious error. The `_b64d` function in the loader confirms it builds its index from `_alphabet` and not from the standard table.

**Layer two is RC4**, and the key is `_k64`, which is itself encoded. The catch is that `_k64` has to be decoded with the custom alphabet as well, not the standard one. This is the thing most likely to go wrong, because `LD/d/h24/dHJZ0y+LGrFLA==` decodes happily under standard base64 and hands back a wrong 16 byte key.

```bash
python3 - <<'EOF'
ALPH = "qYPwzs07b9MUeLZcrHEhyWGt/OX35IaSAxJp2Qv6Rjf1oNuB+4FdClD8KinVTkgm"

def b64d(s):
    s = "".join(s.split())
    out = bytearray()
    for i in range(0, len(s), 4):
        c = [ALPH.find(s[i+j]) if i+j < len(s) and s[i+j] != '=' else 0 for j in range(4)]
        ch = (c[0] << 18) | (c[1] << 12) | (c[2] << 6) | c[3]
        out.append((ch >> 16) & 0xFF)
        if i+2 < len(s) and s[i+2] != '=': out.append((ch >> 8) & 0xFF)
        if i+3 < len(s) and s[i+3] != '=': out.append(ch & 0xFF)
    return bytes(out)

def rc4(key, data):
    S = list(range(256)); j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0; out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)

key = b64d("LD/d/h24/dHJZ0y+LGrFLA==")
print("RC4 key =", key)

for f in ['gpv0IRMtvto6e8t2.txt', '0u25lAqY58or53ra.js', 'HzjNPgRE9ir92e38.txt']:
    pt = rc4(key, b64d(open(f).read()))
    print("\n###", f, "->", len(pt), "bytes")
    print(pt.decode('utf8', 'replace')[:700])
EOF
```

How each piece works:

`b64d` is the loader's own decoder rewritten in Python. Four input characters carry 24 bits, so I shift them into one integer and pull three bytes back out. `ALPH.find` is what swaps in the custom alphabet. I handle `=` the same way the loader does, so short final groups come out the same length.

`rc4` is standard RC4. The first loop is the key scheduling algorithm, which shuffles a 256 byte state array using the key. The second loop makes the keystream and XORs it over the data. RC4 is symmetric, so this one function both encrypts and decrypts.

Output, starting with the key:

```text
RC4 key = b'7f3a91c4b8e05d26'
```

That is the confirmation I wanted. The config I decoded from memory had `"secret_ref":"ref-7f3a91c4"`, and this key starts with exactly `7f3a91c4`. Two separate artifacts, one on disk and one in memory, agreeing with each other. So the key is right.

Then the payloads:

```text
### gpv0IRMtvto6e8t2.txt
  System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
  AppContextSwitches ... UseUnsafeBinaryFormatterSerialization  True
  Antino.Stage2.GateBypass   stage_1

### 0u25lAqY58or53ra.js
// Antino stage-2 orchestrator (decrypted at runtime, executed with eval())
var _ax  = new ActiveXObject("System.Windows.Forms.AxHost+State");
var _bst = new ActiveXObject("System.Runtime.Serialization.Formatters.Binary.BinaryFormatter");
try { _cfg.DisableSerializationGuard(1); _bst.Deserialize(_mem[1]); } catch (e) { }
try { _ax.Bind(_mem[2]); } catch (e2) { ... AttachEmbeddedPayload("TestAssembly.dll"); }
// TestAssembly.dll then downloads the decoy + sideload bundle and launches
// GatherOsState.exe, which side-loads slc.dll (Antino).

### HzjNPgRE9ir92e38.txt
  System.Windows.Forms.AxHost+State   ActivitySurrogateSelector
  TestAssembly.dll   Antino.Stage2.PayloadLoader   stage_2
  oauth_client_id=9f2c1d4b-7e3a-4b18-9c05-6ad11f4e8b23
  oauth_tenant_id=7c1a9d40-5b62-4e88-9a13-2d6f0c8e4b57
  oauth_scope=https://graph.microsoft.com/.default
  oauth_flow=client_credentials
  token_endpoint=https://login.microsoftonline.com/7c1a9d40-.../oauth2/v2.0/token
  mailbox=md-archive@outlook.com
  drive_id=b!4e9c17a2f5d84c6ba07c3e19d2f8b645
  secret_ref=ref-7f3a91c4
  MZ......PE..  (embedded TestAssembly.dll)
```

There it is. `oauth_client_id=9f2c1d4b-7e3a-4b18-9c05-6ad11f4e8b23`. The value the Entra audit said was recoverable only from the implant.

It is useful to think about why it was kept here and not in the config. The config blob is what ends up in a memory dump of a long running process, and that is the thing a responder is most likely to collect. The client id lives one layer back, in a stage-2 blob that gets fetched, decrypted in memory, used, and never written to disk in clear form. By splitting the secrets across stages, capturing the implant does not hand over the cloud identity.

The rest of that blob also answers "no alert fired". The chain is `BinaryFormatter` deserialization abuse. First `gpv0IRMtvto6e8t2.txt` flips the .NET switch `UseUnsafeBinaryFormatterSerialization` to `True`, which disables the guard that blocks these gadget chains. Then `HzjNPgRE9ir92e38.txt` uses the `AxHost+State` plus `ActivitySurrogateSelector` gadget to load an embedded .NET assembly straight into `mshta.exe` memory. No file is written for that stage, so there is nothing for a scanner to find.

## Step 5: putting the flag together

With no flag format on the page, I submitted the obvious thing first.

```text
flag{9f2c1d4b-7e3a-4b18-9c05-6ad11f4e8b23}
```

Rejected. So were the campaign code on its own, the config digest from the heartbeat, the dead drop mailbox, and the operator domain. Five attempts gone. I was confident in the analysis but completely blind on the shape of the answer.

What broke it open was a partial flag that leaked in the event chat and then got deleted.

```text
flag{TW0626-A7F3'
```

Truncated, but it was enough. The flag starts with the campaign code, which means it is a composite and not a single value. And once I knew that, the rest wrote itself. The first half is `campaign_code`, which came out of the memory dump, and the missing half is the thing the whole challenge was built around, the client id out of stage-2.

```text
flag{TW0626-A7F3_9f2c1d4b-7e3a-4b18-9c05-6ad11f4e8b23}
```

Accepted.

So the format was:

```text
flag{<campaign_code>_<oauth_client_id>}
```

Looking back, that is the whole challenge in one line. One half proves you found and decoded the inert record inside the machine. The other half proves you went back through the delivery chain, got past the custom base64 and the RC4, and recovered the cloud identity the attacker had deleted from Entra. Neither half on its own shows you did both.

### Flag

```text
flag{TW0626-A7F3_9f2c1d4b-7e3a-4b18-9c05-6ad11f4e8b23}
```

### The fix

This intrusion is hard to stop with signatures, because there is almost nothing to sign. Every running process was signed by Microsoft and the C2 is Microsoft's own cloud. So the fixes are all about behaviour and about the tenant.

**`.hta` attachments should never reach a mailbox.** The chain begins with Outlook writing `CSIS_Indo-Pacific_Forecast_2026.hta` to Temp. HTA files are scripts that Windows runs with full access, and no business process needs one arriving by email. Blocking the type at the gateway removes the entry point completely.

**`mshta.exe` spawning from Outlook is the single best detection here.** Office applications do not normally start script hosts. That one parent and child pair, `OUTLOOK.EXE` starting `mshta.exe`, is worth an alert on its own, and it fired at `09:43:18` with everything else still ahead of it.

**DLL side loading is detectable by location, not by content.** The malicious `slc.dll` is unsigned and it sits next to a signed Microsoft binary in a user writable folder. A signed Microsoft executable running from `AppData\Local\Temp` and loading an unsigned DLL from its own directory is abnormal regardless of what the DLL contains. Application control that only allows execution from `Program Files` and `Windows` stops it outright.

**The cloud side needs its own review.** The dead drop runs on an Entra application with client credentials, so it survives any password reset and any endpoint cleanup. Containment has to include listing applications with Application level Graph permissions such as `Mail.ReadWrite` and `Files.ReadWrite.All`, checking who consented to them and when, and removing credentials on anything unrecognised. The attacker deleted theirs during cleanup, which is why the audit log in this challenge shows `<NOT RECOVERED>` for the client id.

Note that this also means an organisation cannot block the C2 at the network layer. The traffic goes to `graph.microsoft.com` and `login.microsoftonline.com`, and the delivery used Cloudflare Pages. Every one of those is infrastructure the business depends on.

---

[Back to this event](README.md) · [All writeups](../README.md)
