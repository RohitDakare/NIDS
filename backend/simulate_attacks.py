import time
import socket
import random
import threading
import sys

def send_syn_flood(target_ip, target_port, duration=5):
    """Simulate a SYN flood using raw sockets (requires admin) or just high rate connection attempts"""
    print(f"[*] Starting SYN/Connection Flood on {target_ip}:{target_port} for {duration} seconds...")
    timeout = time.time() + duration
    count = 0
    while time.time() < timeout:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect_ex((target_ip, target_port))
            s.close()
            count += 1
        except:
            pass
    print(f"[*] Sent {count} connection attempts.")

def send_port_scan(target_ip, start_port=50, end_port=150):
    """Simulate a Port Scan"""
    print(f"[*] Starting Port Scan on {target_ip} from port {start_port} to {end_port}...")
    for port in range(start_port, end_port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect_ex((target_ip, port))
            s.close()
            if port % 20 == 0:
                time.sleep(0.01) # throttled slightly
        except:
            pass
    print("[*] Port Scan completed.")

def send_suspicious_payloads(target_ip, target_port=80):
    """Send packets with suspicious signatures"""
    payloads = [
        b"GET /etc/passwd HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"UNION SELECT 1, user(), 3 --",
        b"User-Agent: sqlmap/1.4.7",
        b"eval(base64_decode('...'))",
        b"<script>alert(1)</script>"
    ]
    
    print(f"[*] Sending Suspicious Payloads to {target_ip}:{target_port}...")
    for p in payloads:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_ip, target_port))
            s.send(p)
            s.close()
            print(f"  [+] Sent payload: {p[:20]}...")
        except Exception as e:
            # If server not listening, we might just fail, but sniffer should see packets if we use raw, 
            # but for standard socket we need a listener. 
            # Sending to localhost:8000 (the API server) as it is listening.
            print(f"  [-] Failed to send payload: {e}")

if __name__ == "__main__":
    target = "127.0.0.1"
    
    # We will send traffic to the API port (8000) and dashboard port (3000) to ensure they are captured by Loopback
    
    print("--- STARTING ATTACK SIMULATION ---")
    
    t1 = threading.Thread(target=send_port_scan, args=(target, 7000, 7100))
    t1.start()
    
    t2 = threading.Thread(target=send_syn_flood, args=(target, 8000, 5))
    t2.start()
    
    t1.join()
    t2.join()
    
    send_suspicious_payloads(target, 8000)
    
    print("--- ATTACK SIMULATION FINISHED ---")
