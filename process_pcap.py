import pyshark
import os
from datetime import datetime

def process_pcap(input_file, output_file):
    print(f"Processing {input_file}...")
    cap = pyshark.FileCapture(input_file)
    
    # Initialize lists to store packet details
    src_ips = []
    dst_ips = []
    dst_ports = []  # Destination Port
    protocols = []
    lengths = []
    timestamps = []  # Store packet timestamps as strings
    fwd_packet_lengths = []
    bwd_packet_lengths = []
    fwd_timestamps = []
    bwd_timestamps = []
    fwd_iats = []
    bwd_iats = []
    fwd_headers = []
    bwd_headers = []
    fin_flags = []
    psh_flags = []
    ack_flags = []
    
    for packet in cap:
        try:
            src = packet.ip.src
            dst = packet.ip.dst
            dst_port = packet.tcp.dstport if hasattr(packet, 'tcp') else None  # Destination Port
            proto = packet.highest_layer
            length = packet.length
           # Get the raw timestamp

            timestamp_str = packet.frame_info.time  # e.g., "Apr 10, 2025 12:59:55.123456"
        
            # Parse the full timestamp (including year) and handle milliseconds
            timestamp_obj = datetime.strptime(timestamp_str.split('.')[0], '%b %d, %Y %H:%M:%S')
        
            # Format to desired output: 'YYYY-MM-DD HH:MM:SS'
            timestamp_str = timestamp_obj.strftime('%Y-%m-%d %H:%M:%S')
            
            # Store packet details
            src_ips.append(src)
            dst_ips.append(dst)
            dst_ports.append(dst_port)
            protocols.append(proto)
            lengths.append(length)
            timestamps.append(timestamp_str)
            
            # For forward and backward packet lengths, you might need to differentiate based on packet direction
            if packet.tcp and packet.tcp.srcport > packet.tcp.dstport:
                fwd_packet_lengths.append(length)
                fwd_timestamps.append(timestamp_str)
                if hasattr(packet.tcp, 'flags'):
                    if packet.tcp.flags == 'F':
                        fin_flags.append(1)
                    elif packet.tcp.flags == 'P':
                        psh_flags.append(1)
                    elif packet.tcp.flags == 'A':
                        ack_flags.append(1)
                if hasattr(packet.tcp, 'options'):
                    for option in packet.tcp.options:
                        if option[0] == 'MSS':
                            fwd_headers.append(option[1])
            else:
                bwd_packet_lengths.append(length)
                bwd_timestamps.append(timestamp_str)
                if hasattr(packet.tcp, 'flags'):
                    if packet.tcp.flags == 'F':
                        fin_flags.append(1)
                    elif packet.tcp.flags == 'P':
                        psh_flags.append(1)
                    elif packet.tcp.flags == 'A':
                        ack_flags.append(1)
                if hasattr(packet.tcp, 'options'):
                    for option in packet.tcp.options:
                        if option[0] == 'MSS':
                            bwd_headers.append(option[1])
            
            # Calculate IATs
            if len(fwd_timestamps) > 1:
                # For simplicity, skip calculating IATs for now
                pass
            if len(bwd_timestamps) > 1:
                # For simplicity, skip calculating IATs for now
                pass
                
        except AttributeError:
            pass  # Skip packets without IP layer

    # Save basic packet details to CSV
    with open(output_file, 'w') as f:
        f.write("Source,Destination,Destination Port,Protocol,Length,Timestamp\n")
        for i in range(len(src_ips)):
            f.write(f"{src_ips[i]},{dst_ips[i]},{dst_ports[i]},{protocols[i]},{lengths[i]},{timestamps[i]}\n")

    return {
        'dst_ports': dst_ports,
        'fwd_packet_lengths': fwd_packet_lengths,
        'bwd_packet_lengths': bwd_packet_lengths,
        'timestamps': timestamps,
        'fwd_timestamps': fwd_timestamps,
        'bwd_timestamps': bwd_timestamps,
        'fwd_iats': fwd_iats,
        'bwd_iats': bwd_iats,
        'fwd_headers': fwd_headers,
        'bwd_headers': bwd_headers,
        'fin_flags': fin_flags,
        'psh_flags': psh_flags,
        'ack_flags': ack_flags,
    }

if __name__ == "__main__":
    # ABSOLUTE PATH
    input_file = os.path.join("C:\\Users\\narayan\\network_traffic_analysis\\data\\raw", "live_traffic.pcap")
    # ABSOLUTE PATH
    output_file = os.path.join("C:\\Users\\narayan\\network_traffic_analysis\\data\\processed", "traffic.csv")
    packet_details = process_pcap(input_file, output_file)
