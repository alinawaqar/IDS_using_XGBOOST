import socket
import time

target_ip = "192.168.20.128"  # your real Wi-Fi IPv4 (was 127.0.0.1 - loopback, never captured)
target_port = 8000

print(f"Sending rapid traffic burst to {target_ip}:{target_port} ...")

for i in range(500):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect_ex((target_ip, target_port))
        s.close()
    except Exception:
        pass

    if (i + 1) % 100 == 0:
        print(f"  {i + 1}/500 sent...")

print("Done!")