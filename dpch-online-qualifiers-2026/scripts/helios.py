import socket
import json

HOST = "52.146.88.61"
PORT = 35815   # naya port

def mod_inverse(a, mod):
    return pow(a, -1, mod)

def lagrange_at_zero(points, prime):
    secret = 0
    k = len(points)
    for i in range(k):
        xi, yi = points[i]
        num = yi
        den = 1
        for j in range(k):
            if i == j:
                continue
            xj = points[j][0]
            num = (num * (0 - xj)) % prime
            den = (den * (xi - xj)) % prime
        inv_den = mod_inverse(den, prime)
        secret = (secret + num * inv_den) % prime
    return secret

s = socket.socket()
s.settimeout(30)
print(f"Connecting to {HOST}:{PORT}...")
s.connect((HOST, PORT))
print("Connected!\n")

buffer = ""
while True:
    try:
        data = s.recv(8192)
        if not data:
            print("\nConnection closed")
            break
        buffer += data.decode(errors="replace")

        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            line = line.strip()
            if not line:
                continue

            print(line)

            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            if "shares" in msg and "prime" in msg:
                prime = msg["prime"]
                shares = msg["shares"]
                threshold = msg.get("threshold", len(shares))
                points = shares[:threshold]

                secret = lagrange_at_zero(points, prime)
                reply = {"secret": secret}
                reply_str = json.dumps(reply) + "\n"

                print(f"\n>>> Sending: {reply_str.strip()}")
                s.sendall(reply_str.encode())

    except socket.timeout:
        print("\nTimeout")
        break
    except Exception as e:
        print("\nError:", e)
        break

s.close()
print("\nDone")