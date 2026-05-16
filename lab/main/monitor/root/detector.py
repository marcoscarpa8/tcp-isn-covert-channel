#!/usr/bin/env python3
"""
detector.py — Shannon entropy detector for TCP ISN covert channel
==================================================================

Anomaly-based detection: analyzes the byte-level entropy of TCP Initial
Sequence Numbers (ISN) in SYN packets to detect data encoded in the ISN field.

Course alignment:
  - M4 (Packet Analysis): Scapy rdpcap + programmatic packet filtering
    (ref: M4 slide 50 — "read a capture and filter by protocol")
  - M8 (IDS/IPS): Anomaly-based detection — "establishes a baseline of
    normal behavior, detects deviations" (ref: M8 slide 12)

Theory:
  Normal ISNs (RFC 6528): kernels generate pseudo-random 32-bit values.
    → Byte-level Shannon entropy ≈ 7.5 – 8.0 bits/byte (near-uniform).

  Covert ISNs (our channel): magic 0xCAFE in high 16 bits + 2 data bytes
  in low 16 bits.
    → High bytes are ALWAYS 0xCA and 0xFE (zero entropy contribution).
    → Byte entropy drops significantly (typically 3.0 – 5.0 bits/byte).

  Detection signal: if a source's SYN ISNs have entropy well below the
  normal ~7.5 threshold, the ISNs likely carry structured (non-random) data.

Usage:
  # Offline analysis (pcap file)
  python3 detector.py covert_session.pcap

  # Offline with custom threshold and window size
  python3 detector.py covert_session.pcap --threshold 6.0 --window 30

  # Live sniffing on an interface (Ctrl+C to stop and analyze)
  python3 detector.py --live eth0

  # Compare baseline (normal) vs covert traffic
  python3 detector.py baseline.pcap
  python3 detector.py covert_session.pcap
"""

import sys
import math
from collections import defaultdict, Counter

from scapy.all import rdpcap, sniff, TCP, IP


# =========================================================================
# Core functions
# =========================================================================

def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of a byte sequence (bits per byte).

    H = - SUM(p_i * log2(p_i)) for each unique byte value i.

    Perfect uniform random over 256 symbols → H = 8.0 bits/byte.
    All bytes identical → H = 0.0 bits/byte.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def extract_syn_isns(packets):
    """
    Extract ISN (tcp.seq) from SYN-only packets, grouped by source IP.

    Filters: TCP flag SYN=1, ACK=0 (pure initial SYN, not SYN+ACK).
    Same logic as Wireshark filter: tcp.flags.syn==1 && tcp.flags.ack==0
    (ref: M4 slide 30, Exercise 7)

    Returns:
        dict { src_ip: [isn_int, isn_int, ...] }
    """
    isns = defaultdict(list)
    for pkt in packets:
        if TCP in pkt and IP in pkt:
            flags = pkt[TCP].flags
            # SYN set (0x02) and ACK not set (0x10)
            if flags & 0x02 and not (flags & 0x10):
                src = pkt[IP].src
                isns[src].append(pkt[TCP].seq)
    return isns


def isn_to_bytes(isn_list: list) -> bytes:
    """Convert list of 32-bit ISN integers to raw byte sequence."""
    raw = b''
    for isn in isn_list:
        raw += (isn & 0xFFFFFFFF).to_bytes(4, byteorder='big')
    return raw


def high_bytes_entropy(isn_list: list) -> float:
    """
    Entropy of only the HIGH 16 bits of each ISN.
    Our covert channel places magic 0xCAFE here → near-zero entropy.
    Normal ISNs → ~7.5+ entropy in the high bytes too.
    """
    raw = b''
    for isn in isn_list:
        high = (isn >> 16) & 0xFFFF
        raw += high.to_bytes(2, byteorder='big')
    return shannon_entropy(raw)


def low_bytes_entropy(isn_list: list) -> float:
    """
    Entropy of only the LOW 16 bits of each ISN.
    Our covert channel places data here → entropy depends on data content.
    Normal ISNs → ~7.5+ entropy.
    """
    raw = b''
    for isn in isn_list:
        low = isn & 0xFFFF
        raw += low.to_bytes(2, byteorder='big')
    return shannon_entropy(raw)


# =========================================================================
# Analysis engine
# =========================================================================

def analyze(isns_by_src: dict, window_size: int = 30,
            threshold: float = 6.0) -> list:
    """
    Analyze ISN entropy per source IP in sliding windows.

    Args:
        isns_by_src:  { src_ip: [isn_values] }
        window_size:  number of ISNs per analysis window
        threshold:    full-ISN entropy below this → flag as suspicious

    Returns:
        list of result dicts with entropy metrics
    """
    results = []

    for src, isns in isns_by_src.items():
        # If fewer ISNs than window, analyze all at once
        windows = []
        if len(isns) < window_size:
            windows.append((0, isns))
        else:
            step = max(1, window_size // 2)
            for start in range(0, len(isns) - window_size + 1, step):
                windows.append((start, isns[start:start + window_size]))

        for start, window in windows:
            full_bytes = isn_to_bytes(window)
            ent_full = shannon_entropy(full_bytes)
            ent_high = high_bytes_entropy(window)
            ent_low  = low_bytes_entropy(window)
            flagged  = ent_full < threshold

            results.append({
                'src_ip':      src,
                'window':      f'{start}-{start + len(window) - 1}',
                'isn_count':   len(window),
                'entropy_full': ent_full,
                'entropy_high': ent_high,
                'entropy_low':  ent_low,
                'flagged':     flagged,
            })

    return results


# =========================================================================
# Reporting
# =========================================================================

HEADER = (
    f"\n{'='*80}\n"
    f"  ISN Entropy Analysis — Covert Channel Detection\n"
    f"  Method: Shannon entropy on TCP SYN sequence numbers\n"
    f"  Ref: M8 slide 12 (anomaly-based detection), M4 slide 50 (Scapy inspection)\n"
    f"{'='*80}"
)

def print_report(results: list, threshold: float):
    """Print formatted analysis report."""
    print(HEADER)
    print(f"\n  Threshold: {threshold:.1f} bits/byte"
          f"  (normal ISN ≈ 7.5+, covert ISN ≈ 3.0-5.0)\n")

    print(f"  {'Source IP':<18} {'Window':<12} {'#ISN':<6} "
          f"{'Full H':<9} {'High H':<9} {'Low H':<9} {'Status'}")
    print(f"  {'-'*80}")

    for r in results:
        status = "*** SUSPICIOUS ***" if r['flagged'] else "    normal"
        print(f"  {r['src_ip']:<18} {r['window']:<12} {r['isn_count']:<6} "
              f"{r['entropy_full']:<9.4f} {r['entropy_high']:<9.4f} "
              f"{r['entropy_low']:<9.4f} {status}")

    print(f"  {'-'*80}")

    flagged = [r for r in results if r['flagged']]
    if flagged:
        suspects = sorted(set(r['src_ip'] for r in flagged))
        print(f"\n  ALERT: {len(flagged)} window(s) flagged "
              f"(entropy < {threshold:.1f})")
        print(f"  Suspect source(s): {', '.join(suspects)}")
        print(f"\n  Interpretation: the ISN values from these sources show")
        print(f"  non-random structure consistent with data encoded in the")
        print(f"  TCP sequence number field (ISN covert channel).")
        print(f"\n  Key indicator: 'High H' near 0 → fixed magic bytes in")
        print(f"  upper 16 bits of ISN (0xCAFE in our channel).")
    else:
        print(f"\n  OK: No anomalies detected. All ISN distributions appear")
        print(f"  consistent with normal pseudo-random generation (RFC 6528).")

    print()


# =========================================================================
# Main
# =========================================================================

def parse_args(argv):
    """Parse command-line arguments."""
    threshold = 6.0
    window    = 30
    live_iface = None
    pcap_file  = None

    i = 1
    while i < len(argv):
        arg = argv[i]
        if arg == '--threshold' and i + 1 < len(argv):
            threshold = float(argv[i + 1]); i += 2
        elif arg == '--window' and i + 1 < len(argv):
            window = int(argv[i + 1]); i += 2
        elif arg == '--live' and i + 1 < len(argv):
            live_iface = argv[i + 1]; i += 2
        elif arg in ('-h', '--help'):
            print(__doc__)
            sys.exit(0)
        else:
            pcap_file = arg; i += 1

    return pcap_file, live_iface, threshold, window


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file> [--threshold F] [--window N]")
        print(f"       {sys.argv[0]} --live <iface> [--threshold F] [--window N]")
        print(f"       {sys.argv[0]} --help")
        sys.exit(1)

    pcap_file, live_iface, threshold, window = parse_args(sys.argv)

    # --- Load packets ---
    if live_iface:
        print(f"[*] Live sniffing on {live_iface} — press Ctrl+C to stop and analyze...")
        try:
            packets = sniff(iface=live_iface,
                            filter="tcp[tcpflags] & tcp-syn != 0",
                            store=True)
        except KeyboardInterrupt:
            print("\n[*] Capture stopped by user.")
            packets = sniff(iface=live_iface, store=True, count=0)
    elif pcap_file:
        print(f"[*] Reading {pcap_file} ...")
        packets = rdpcap(pcap_file)
    else:
        print("Error: specify a pcap file or --live <interface>")
        sys.exit(1)

    print(f"[*] Total packets loaded: {len(packets)}")

    # --- Extract ISNs ---
    isns = extract_syn_isns(packets)

    if not isns:
        print("[!] No SYN-only packets found in the capture.")
        sys.exit(0)

    print(f"[*] SYN-only packets found from {len(isns)} source(s):")
    for src, vals in sorted(isns.items()):
        print(f"    {src}: {len(vals)} SYNs")

    # --- Analyze ---
    results = analyze(isns, window_size=window, threshold=threshold)
    print_report(results, threshold)


if __name__ == '__main__':
    main()
