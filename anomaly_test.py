import socket

target_ip = "192.168.137.1"
target_port = 80  # Or another port your NIDS is monitoring

for i in range(1000):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((target_ip, target_port))
    except:
        pass
    s.close()