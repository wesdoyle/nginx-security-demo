import sys
from scapy.all import sniff, IP, TCP, Raw
from collections import defaultdict
import argparse

def analyze_packet(packet):
    if IP in packet and TCP in packet and Raw in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        payload = packet[Raw].load
        return (src_ip, dst_ip, src_port, dst_port, payload)
    return None

def capture_traffic(interface, port, duration):
    print(f"Capturing traffic on interface {interface}, port {port} for {duration} seconds...")
    packets = sniff(iface=interface, filter=f"tcp and port {port}", timeout=duration)
    
    connections = defaultdict(list)
    for packet in packets:
        result = analyze_packet(packet)
        if result:
            src_ip, dst_ip, src_port, dst_port, payload = result
            connection_key = (src_ip, dst_ip, src_port, dst_port)
            connections[connection_key].append(payload)
    
    return connections

def print_captured_data(connections, is_encrypted):
    print("\nCaptured Data:")
    for (src_ip, dst_ip, src_port, dst_port), payloads in connections.items():
        print(f"\nConnection: {src_ip}:{src_port} <-> {dst_ip}:{dst_port}")
        for i, payload in enumerate(payloads, 1):
            if is_encrypted:
                print(f"  Payload {i}: [Encrypted data of length {len(payload)}]")
            else:
                try:
                    decoded = payload.decode('utf-8')
                    print(f"  Payload {i}: {decoded}")
                except UnicodeDecodeError:
                    print(f"  Payload {i}: [Binary data of length {len(payload)}]")

def main():
    parser = argparse.ArgumentParser(description="Capture and analyze network traffic")
    parser.add_argument("interface", help="Network interface to capture traffic on")
    parser.add_argument("port", type=int, help="Port to capture traffic on")
    parser.add_argument("--duration", type=int, default=30, help="Duration of capture in seconds")
    parser.add_argument("--encrypted", action="store_true", help="Indicate if the traffic is expected to be encrypted")
    args = parser.parse_args()

    connections = capture_traffic(args.interface, args.port, args.duration)
    print_captured_data(connections, args.encrypted)

if __name__ == "__main__":
    main()