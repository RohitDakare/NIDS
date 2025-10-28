import socket
import time

target_ip = "192.168.1.102"
target_port = 80  # Or another port your NIDS is monitoring

for i in range(1000):
    try:
        with socket.create_connection((target_ip, target_port), timeout=2) as s:
            pass  # Connection established and immediately closed
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        # Optionally log the error or just pass
        pass
    time.sleep(0.01)  # Small delay to avoid overwhelming the system