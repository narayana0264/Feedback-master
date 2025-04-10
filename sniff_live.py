from scapy.all import sniff, wrpcap
import os

def capture_packets(interface, output_file):
    print(f"Capturing live traffic on {interface}...")
    packets = sniff(iface=interface, count=100)  # Capture 100 packets
    wrpcap(output_file, packets)
    print(f"Packets saved to {output_file}")

if __name__ == "__main__":
    interface = "Realtek PCIe GbE Family Controller"  
    output_file = os.path.join("C:\\Users\\narayan\\network_traffic_analysis\\data\\raw", "live_traffic.pcap")
    capture_packets(interface, output_file)
