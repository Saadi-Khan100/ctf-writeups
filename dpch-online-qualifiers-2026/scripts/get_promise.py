import socket

HOST = "52.146.88.61"
PORT = 36518

s = socket.socket()
s.settimeout(30)
s.connect((HOST, PORT))

data = b""
while True:
    try:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    except:
        break

open("promise_output.txt", "wb").write(data)
print("Saved", len(data), "bytes")
print(data[:300].decode(errors="replace"))
s.close()