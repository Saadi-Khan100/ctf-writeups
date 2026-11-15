# Apartment

## Understanding the challenge

|  |  |
| --- | --- |
| Category | Blue Team / Incident Response |
| Event | DPCH Online Qualifiers (Cydea Range platform) |
| Team | Pwnag3 |
| Files given | `evidence.tgz` (Sysmon and Security logs for three hosts, DNS, proxy, firewall, VPN, mail gateway, quarantined files) |
| Flag format | `flag{key:key}` |

### What the challenge says

A property management company was breached. The incident response team needs two indicators to put on the blocklist. The command and control domain the malware talks to, and the file identity of the malware itself. Those two with a colon between them make the flag.

### Reading the format properly

I lost attempts on this, so I am putting it first.

The word "blocklist" made me assume both indicators were network things. So I expected a domain and an IP address. I submitted that twice, in both orders.

```text
flag{sync.tenant-data-api.net:91.219.236.14}
flag{91.219.236.14:sync.tenant-data-api.net}
```

Both wrong. When I read the wording again, it asks for the C2 domain and the file identity of the implant. A file's identity in incident response is its hash. It is not the address the file talks to. And a blocklist is not only firewall rules. It also covers file hashes that get pushed to the endpoint agent.

So the two halves come from two different layers. One from the network, one from the host. Once I accepted that, the challenge became simple.

## Opening the evidence

```bash
mkdir -p ~/apartment/ev && cd ~/apartment/ev
tar xzf '../evidence (7).tgz'
find . -type f -printf '%10s  %P\n' | sort -k2
```

Output:

```text
      1023  evidence/artifacts/quarantine/manifest.csv
    180000  evidence/artifacts/quarantine/q-0001.bin
    217331  evidence/artifacts/quarantine/q-0002.bin
    254662  evidence/artifacts/quarantine/q-0003.bin
    291993  evidence/artifacts/quarantine/q-0004.bin
    329324  evidence/artifacts/quarantine/q-0005.bin
    184334  evidence/artifacts/quarantine/q-0006.bin
    403986  evidence/artifacts/quarantine/q-0007.bin
    201317  evidence/artifacts/quarantine/q-0008.bin
   2222276  evidence/logs/dns/dns_queries.log
    879040  evidence/logs/email/mail_gateway.log
   1807423  evidence/logs/endpoint/DC01_security.jsonl
   1292449  evidence/logs/endpoint/SRV-APP01_security.jsonl
   3044089  evidence/logs/endpoint/SRV-APP01_sysmon.jsonl
   1772100  evidence/logs/endpoint/WKS-AP-014_security.jsonl
   3809648  evidence/logs/endpoint/WKS-AP-014_sysmon.jsonl
   2916221  evidence/logs/firewall/paloalto_traffic.csv
   2562389  evidence/logs/proxy/squid_access.log
    560687  evidence/logs/vpn/vpn_auth.log
```

I noticed two things before reading anything.

Only one workstation, `WKS-AP-014`, has a Sysmon log as well as a Security log. Sysmon records process creation, network connections, file creation and registry writes. That is far more detail than the standard Windows Security log gives. The organisers gave full Sysmon for exactly one workstation, which is a hint about where the infection is.

There are eight quarantined files, and there is a manifest that explains them. The manifest is tiny, so I read that first.

## Step 1: the quarantine manifest

```bash
cat evidence/artifacts/quarantine/manifest.csv
```

Output:

```text
artifact,host,original_path,captured_at,collector,reason
q-0001.bin,WKS-AP-004,C:\Users\a.perera\AppData\Local\Temp\TeamsUpdate.exe,2026-11-02T05:14:22.412Z,MDE,Benign update package
q-0002.bin,WKS-AP-019,C:\Users\k.silva\Downloads\Adobe_Reader_Update.exe,2026-11-02T06:02:51.005Z,MDE,Benign update package
q-0003.bin,WKS-AP-031,C:\Users\a.perera\Downloads\TenantUpdate.exe,2026-11-02T07:48:09.331Z,MDE,User-reported download
q-0004.bin,SRV-FILE02,C:\Windows\Temp\7zO4A21F.tmp,2026-11-02T08:29:44.118Z,MDE,Archive staging
q-0005.bin,WKS-AP-008,C:\Users\m.weerasinghe\AppData\Local\Temp\chrome_update.exe,2026-11-02T09:05:12.774Z,MDE,Benign update package
q-0006.bin,WKS-AP-014,C:\Users\n.fernando\AppData\Local\Temp\TenantUpdate.exe,2026-11-02T10:11:38.902Z,MDE,Behavioural quarantine
q-0007.bin,SRV-APP01,C:\Windows\Temp\lsass_7712.dmp,2026-11-02T10:14:02.219Z,MDE,Credential-dump signature
q-0008.bin,WKS-AP-026,C:\Users\t.herath\Downloads\invoice_2026_11.pdf.exe,2026-11-02T11:41:57.660Z,MDE,Blocked attachment
```

The `reason` column does the work here. Five of the eight say "Benign update package", "Archive staging", "User-reported download" or "Blocked attachment". Those are the categories an endpoint product uses when it collected something just for completeness, or when it stopped a file before it ran.

One of them says "Behavioural quarantine". That is a completely different statement. Behavioural detection means the product watched the file do something and decided it was bad from its actions. Which means the file ran. And it is on `WKS-AP-014`, the one host with full Sysmon.

One more thing stood out. The name `TenantUpdate.exe` shows up twice, on two different hosts, under two different users.

- `q-0003.bin` on WKS-AP-031, in `a.perera`'s Downloads folder, "User-reported download"
- `q-0006.bin` on WKS-AP-014, in `n.fernando`'s Temp folder, "Behavioural quarantine"

Same file name, two separate collections. So either they are copies of one file, or they are two different files with the same name. I could not assume, so I checked.

```bash
sha256sum evidence/artifacts/quarantine/q-*.bin
```

Output:

```text
acc9b08900ca90af918293484c6c861b0476368478644db178b4dd02914adde3  q-0001.bin
79238d2338f8b6a31df16331298e630555e2d9ede873ea0f2f6395e9aab67b01  q-0002.bin
a7baa7de656d62ee5a6459058368a2dc0d88a674e4822b5a96fd2351242c0ef9  q-0003.bin
99760f1248c4937b7f08148cffd60d7acba7f3c140b5ffdeaa6386d00e208a38  q-0004.bin
143f95882220eeedc6c6405d3a3523b486016da438c6fb83401c1722cec29025  q-0005.bin
6cc93a19bfcb143437bb4c56b6322bc88a4620bcad09968683eff1f4d4310106  q-0006.bin
c37399d0096ef268b306b92ceeb0251050650119f49afd5f66549e17b845dad4  q-0007.bin
13f9db0af55d0b4bd88933a3b5662d3c0a46e88caee7f3ab0acaead4f63c8fec  q-0008.bin
```

Different hashes. And different file sizes too, 254,662 bytes against 184,334. So these are two genuinely different programs that share a name.

This is the trap in the challenge. Anyone who searches for the file name and hashes the first hit gets the wrong answer. And the wrong answer looks completely fine.

I now had a strong candidate in `6cc93a19...`, but a comment in a manifest is not proof. I needed the host log to show that this exact file ran and talked to a C2.

## Step 2: finding the C2 domain in DNS

The DNS log is 2.2 MB, so I did not read it. I let the shape of the attack tell me what to search for. A C2 domain in this kind of scenario is usually a name built to look like a real company service. So I searched for names in the company's own theme, which is tenants and property management.

```bash
grep -n 'tenant' evidence/logs/dns/dns_queries.log | head -20
```

`-n` prints line numbers, which helps if I want to jump back into the file later with `sed -n`.

One name in the results stood out, because of how rarely it appeared. Normal corporate traffic is noisy. A real service gets queried hundreds of times a day as caches expire. So I counted instead of reading.

```bash
grep -c 'tenant-data-api' evidence/logs/dns/dns_queries.log
grep 'tenant-data-api' evidence/logs/dns/dns_queries.log
```

`-c` counts the matching lines instead of printing them. That one number was the most useful thing I got in this whole challenge.

Output:

```text
1
2026-11-02T09:17:43.857Z query [10.20.4.51] sync.tenant-data-api.net A NOERROR 91.219.236.14
```

Exactly one query, in a 2.2 MB log. A name that is asked for once and never again is not a service anyone uses. It is a name resolved by one program, one time, at one moment.

That single line gave me the domain `sync.tenant-data-api.net` and the address behind it, `91.219.236.14`.

This is a technique I am keeping. In a big DNS log, looking for the names that appear the fewest times is often better than looking for the names that appear the most. Beacons are loud. First stage lookups are quiet.

## Step 3: proving the implant ran, on the host

Now I needed to connect that one DNS line to the file `6cc93a19...`. The Sysmon log for WKS-AP-014 is newline delimited JSON, one event per line. I checked the shape of a record first, instead of guessing the field names.

```bash
head -1 evidence/logs/endpoint/WKS-AP-014_sysmon.jsonl | python3 -m json.tool
```

Output:

```text
{
 "@timestamp": "2026-11-02T03:00:11.655Z",
 "host": "WKS-AP-014",
 "event_id": 3,
 "event": { "category": "network", "action": "network_connection", "outcome": "success" },
 "process": { "pid": 10114, "image": "C:\\Windows\\System32\\cmd.exe" },
 "network": { "direction": "outbound", "protocol": "tcp",
              "destination_ip": "52.96.0.1", "destination_port": 80 }
}
```

Now I know the field names, so I can pull out exactly what I want. These are the Sysmon event IDs that matter here:

- **1** process created
- **3** network connection made
- **11** file created
- **13** registry value set
- **22** DNS query made by a process

Event 22 is the bridge I needed. The DNS server log told me that a machine asked for the domain. Event 22 tells me which process asked.

```bash
grep 'TenantUpdate' evidence/logs/endpoint/WKS-AP-014_sysmon.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line)
    print(d['@timestamp'], 'eid', d['event_id'], d['event']['action'])
    print('   image:', d.get('process', {}).get('image'))
    for k in ('file', 'network', 'registry'):
        if k in d:
            print('   ', k, ':', json.dumps(d[k]))
"
```

I piped `grep` into Python instead of using `jq` because I want to print a different extra field depending on the event type, and that gets awkward in a one line `jq` filter. Running `grep` first also keeps it fast, since Python only has to parse the few lines that matter instead of the whole 3.8 MB file.

Output:

```text
2026-11-02T07:48:07.000Z eid 11 file_created
   image: C:\Program Files\Google\Chrome\Application\chrome.exe
    file : {"path": "C:\\Users\\a.perera\\Downloads\\TenantUpdate.exe", "name": "TenantUpdate.exe"}
2026-11-02T09:17:52.000Z eid 11 file_created
   image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
    file : {"path": "C:\\Users\\n.fernando\\AppData\\Local\\Temp\\TenantUpdate.exe", "name": "TenantUpdate.exe"}
2026-11-02T09:17:53.000Z eid 1 process_created
   image: C:\Users\n.fernando\AppData\Local\Temp\TenantUpdate.exe
2026-11-02T09:17:54.000Z eid 3 network_connection
   image: C:\Users\n.fernando\AppData\Local\Temp\TenantUpdate.exe
    network : {"direction": "outbound", "protocol": "tcp", "destination_ip": "91.219.236.14", "destination_port": 443}
2026-11-02T09:18:00.000Z eid 13 registry_value_set
   image: C:\Users\n.fernando\AppData\Local\Temp\TenantUpdate.exe
    registry : {"key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "value": "TenantPortalSync",
                "data": "C:\\Users\\n.fernando\\AppData\\Local\\Temp\\TenantUpdate.exe"}
2026-11-02T09:18:07.000Z eid 1 process_created
   image: C:\Windows\System32\rundll32.exe
```

Now the two `TenantUpdate.exe` files are completely separated. And what separates them is who wrote each one.

The one at 07:48 was written by **chrome.exe** into a Downloads folder. So a user browsed somewhere and downloaded a file. That is `q-0003.bin`. The user reported it and it was collected. It never shows up again, so it never ran.

The one at 09:17:52 was written by **powershell.exe** into a Temp folder, and one second later it started running. That is `q-0006.bin`. Programs do not normally arrive by PowerShell writing them into Temp.

Then I pulled the events around that C2 address, to get the order right.

```bash
grep '91.219.236.14' evidence/logs/endpoint/WKS-AP-014_sysmon.jsonl | python3 -c "
import sys, json
for line in sys.stdin:
    d = json.loads(line)
    print(d['@timestamp'], 'eid', d['event_id'], d.get('process', {}).get('image'))
"
```

Output:

```text
2026-11-02T09:17:43.908Z eid 22 C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
2026-11-02T09:17:46.000Z eid 3 C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
2026-11-02T09:17:54.000Z eid 3 C:\Users\n.fernando\AppData\Local\Temp\TenantUpdate.exe
```

That first line closes the case. Event 22 at `09:17:43.908` is PowerShell asking DNS for the C2 name. The DNS server logged the same lookup at `09:17:43.857`, fifty one milliseconds earlier. Same moment, two separate sources. One names the process, the other names the domain.

Here is the full chain in order:

```text
09:17:43.857  DNS server   : sync.tenant-data-api.net -> 91.219.236.14
09:17:43.908  Sysmon eid22 : powershell.exe made that lookup
09:17:46      Sysmon eid3  : powershell.exe connects to 91.219.236.14:443
09:17:52      Sysmon eid11 : powershell.exe writes TenantUpdate.exe into Temp
09:17:53      Sysmon eid1  : TenantUpdate.exe starts
09:17:54      Sysmon eid3  : TenantUpdate.exe connects to 91.219.236.14:443 itself
09:18:00      Sysmon eid13 : HKCU Run key "TenantPortalSync" set to that path
09:18:07      Sysmon eid1  : rundll32.exe spawned
10:11:38      MDE          : file quarantined as q-0006.bin
```

So PowerShell resolved the C2, connected to it, pulled the implant down, and then the implant connected to the same C2 on its own and wrote itself into the Run key so it survives a reboot. The persistence value is called `TenantPortalSync`, picked to look like a company service in a list of startup items.

That makes `6cc93a19...` the file that ran, beaconed and persisted. And `a7baa7de...` is a file with the same name that sat in a Downloads folder and did nothing.

### Flag

The two indicators for the blocklist, from two different layers:

- C2 domain, from DNS: `sync.tenant-data-api.net`
- Implant file identity, from the quarantined sample that actually ran: `6cc93a19bfcb143437bb4c56b6322bc88a4620bcad09968683eff1f4d4310106`

```text
flag{sync.tenant-data-api.net:6cc93a19bfcb143437bb4c56b6322bc88a4620bcad09968683eff1f4d4310106}
```

### The fix

The whole chain ran as the user, so none of it needed an administrator.

**PowerShell should not be downloading and running executables.** The implant arrived because `powershell.exe` resolved an external name, connected to it, and wrote a program into the user's Temp folder. Constrained Language Mode plus PowerShell script block logging would have both limited and recorded that. On this host Sysmon captured it, which is the only reason the chain could be reconstructed at all.

**The Run key write was the loudest event in the whole attack.** At `09:18:00` a program running from `AppData\Local\Temp` wrote itself into `HKCU\...\CurrentVersion\Run`. A binary in a temporary folder making itself persistent is almost never legitimate, and Sysmon event 13 on the Run keys is a cheap, high quality alert.

**Blocking the domain is not enough on its own.** `sync.tenant-data-api.net` is one name, and the operator can register another tomorrow. The file hash goes to the endpoint agent, and the behaviour, PowerShell writing an executable into Temp and launching it, is what catches the next campaign when the domain has changed.

One thing the organisation already had right. Full Sysmon on the workstation is what turned a single DNS line into a complete timeline with process names attached. The other two hosts only had the standard Security log, and the same investigation on those would not have been possible.

---

[Back to this event](README.md) · [All writeups](../README.md)
