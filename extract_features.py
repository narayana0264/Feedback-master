import pandas as pd
import numpy as np
import os
from datetime import datetime

def extract_features(input_csv, output_csv):
    print(f"Extracting features from {input_csv}...")
    
    # Load the CSV file
    df = pd.read_csv(input_csv)
    
    # Convert Timestamp column to datetime objects
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
    
    # Load packet details from process_pcap.py output (manually for now)
    packet_details = {
        'dst_ports': [80],  # Example
        'fwd_packet_lengths': [100, 200, 300],
        'bwd_packet_lengths': [50, 75],
        'timestamps': [datetime.now(), datetime.now()],  # Example
        'fwd_timestamps': [datetime.now(), datetime.now()],  # Example
        'bwd_timestamps': [datetime.now(), datetime.now()],  # Example
        'fwd_iats': [0.1, 0.2],
        'bwd_iats': [0.05, 0.1],
        'fwd_headers': [20, 30],
        'bwd_headers': [10, 15],
        'fin_flags': [1],
        'psh_flags': [1],
        'ack_flags': [1],
    }
    
    # Calculate features
    dst_port = packet_details['dst_ports'][0]  # Destination Port
    flow_duration = (df['Timestamp'].max() - df['Timestamp'].min()).total_seconds()  # Flow Duration
    
    # Total Fwd Packets
    total_fwd_packets = len(packet_details['fwd_packet_lengths'])
    
    # Total Length of Fwd Packets
    total_fwd_length = sum(packet_details['fwd_packet_lengths'])
    
    # Packet Length Statistics
    fwd_packet_lengths = packet_details['fwd_packet_lengths']
    bwd_packet_lengths = packet_details['bwd_packet_lengths']
    
    fwd_max_packet_length = max(fwd_packet_lengths) if fwd_packet_lengths else 0
    fwd_min_packet_length = min(fwd_packet_lengths) if fwd_packet_lengths else 0
    fwd_mean_packet_length = np.mean(fwd_packet_lengths) if fwd_packet_lengths else 0
    fwd_std_packet_length = np.std(fwd_packet_lengths) if fwd_packet_lengths else 0
    
    bwd_max_packet_length = max(bwd_packet_lengths) if bwd_packet_lengths else 0
    bwd_min_packet_length = min(bwd_packet_lengths) if bwd_packet_lengths else 0
    bwd_mean_packet_length = np.mean(bwd_packet_lengths) if bwd_packet_lengths else 0
    bwd_std_packet_length = np.std(bwd_packet_lengths) if bwd_packet_lengths else 0
    
    # Flow Bytes/s and Flow Packets/s
    flow_bytes = sum(df['Length'])
    flow_packets = len(df)
    flow_bytes_per_second = flow_bytes / flow_duration if flow_duration > 0 else 0
    flow_packets_per_second = flow_packets / flow_duration if flow_duration > 0 else 0
    
    # Flow IAT Statistics
    timestamps = df['Timestamp']
    iats = []
    for i in range(1, len(timestamps)):
        iats.append((timestamps.iloc[i] - timestamps.iloc[i-1]).total_seconds())
    flow_iat_mean = np.mean(iats) if iats else 0
    flow_iat_std = np.std(iats) if iats else 0
    flow_iat_max = max(iats) if iats else 0
    flow_iat_min = min(iats) if iats else 0
    
    # Fwd IAT Statistics
    fwd_iats = packet_details['fwd_iats']
    fwd_iat_total = sum(fwd_iats) if fwd_iats else 0
    fwd_iat_mean = np.mean(fwd_iats) if fwd_iats else 0
    fwd_iat_std = np.std(fwd_iats) if fwd_iats else 0
    fwd_iat_max = max(fwd_iats) if fwd_iats else 0
    fwd_iat_min = min(fwd_iats) if fwd_iats else 0
    
    # Bwd IAT Statistics
    bwd_iats = packet_details['bwd_iats']
    bwd_iat_total = sum(bwd_iats) if bwd_iats else 0
    bwd_iat_mean = np.mean(bwd_iats) if bwd_iats else 0
    bwd_iat_std = np.std(bwd_iats) if bwd_iats else 0
    bwd_iat_max = max(bwd_iats) if bwd_iats else 0
    bwd_iat_min = min(bwd_iats) if bwd_iats else 0
    
    # Header Lengths
    fwd_header_length = np.mean(packet_details['fwd_headers']) if packet_details['fwd_headers'] else 0
    bwd_header_length = np.mean(packet_details['bwd_headers']) if packet_details['bwd_headers'] else 0
    
    # Packets/s
    fwd_packets_per_second = len(packet_details['fwd_packet_lengths']) / flow_duration if flow_duration > 0 else 0
    bwd_packets_per_second = len(packet_details['bwd_packet_lengths']) / flow_duration if flow_duration > 0 else 0
    
    # Packet Length Statistics
    packet_lengths = df['Length']
    min_packet_length = packet_lengths.min()
    max_packet_length = packet_lengths.max()
    packet_length_mean = packet_lengths.mean()
    packet_length_std = packet_lengths.std()
    packet_length_variance = packet_length_std ** 2
    
    # Flag Counts
    fin_flag_count = len(packet_details['fin_flags'])
    psh_flag_count = len(packet_details['psh_flags'])
    ack_flag_count = len(packet_details['ack_flags'])
    
    # Average Packet Size
    average_packet_size = packet_length_mean
    
    # Subflow Fwd Bytes
    subflow_fwd_bytes = total_fwd_length
    
    # Init Window Bytes
    init_win_bytes_forward = 0  # Requires parsing TCP SYN packets
    init_win_bytes_backward = 0  # Requires parsing TCP SYN packets
    
    # Active and Idle Times
    active_mean = 0  # Requires calculating active times based on packet timestamps
    active_max = 0
    active_min = 0
    idle_mean = 0  # Requires calculating idle times based on packet timestamps
    idle_max = 0
    idle_min = 0
    
    # Save extracted features to CSV
    features = {
        'Destination Port': dst_port,
        'Flow Duration': flow_duration,
        'Total Fwd Packets': total_fwd_packets,
        'Total Length of Fwd Packets': total_fwd_length,
        'Fwd Packet Length Max': fwd_max_packet_length,
        'Fwd Packet Length Min': fwd_min_packet_length,
        'Fwd Packet Length Mean': fwd_mean_packet_length,
        'Fwd Packet Length Std': fwd_std_packet_length,
        'Bwd Packet Length Max': bwd_max_packet_length,
        'Bwd Packet Length Min': bwd_min_packet_length,
        'Bwd Packet Length Mean': bwd_mean_packet_length,
        'Bwd Packet Length Std': bwd_std_packet_length,
        'Flow Bytes/s': flow_bytes_per_second,
        'Flow Packets/s': flow_packets_per_second,
        'Flow IAT Mean': flow_iat_mean,
        'Flow IAT Std': flow_iat_std,
        'Flow IAT Max': flow_iat_max,
        'Flow IAT Min': flow_iat_min,
        'Fwd IAT Total': fwd_iat_total,
        'Fwd IAT Mean': fwd_iat_mean,
        'Fwd IAT Std': fwd_iat_std,
        'Fwd IAT Max': fwd_iat_max,
        'Fwd IAT Min': fwd_iat_min,
        'Bwd IAT Total': bwd_iat_total,
        'Bwd IAT Mean': bwd_iat_mean,
        'Bwd IAT Std': bwd_iat_std,
        'Bwd IAT Max': bwd_iat_max,
        'Bwd IAT Min': bwd_iat_min,
        'Fwd Header Length': fwd_header_length,
        'Bwd Header Length': bwd_header_length,
        'Fwd Packets/s': fwd_packets_per_second,
        'Bwd Packets/s': bwd_packets_per_second,
        'Min Packet Length': min_packet_length,
        'Max Packet Length': max_packet_length,
        'Packet Length Mean': packet_length_mean,
        'Packet Length Std': packet_length_std,
        'Packet Length Variance': packet_length_variance,
        'FIN Flag Count': fin_flag_count,
        'PSH Flag Count': psh_flag_count,
        'ACK Flag Count': ack_flag_count,
        'Average Packet Size': average_packet_size,
        'Subflow Fwd Bytes': subflow_fwd_bytes,
        'Init_Win_bytes_forward': init_win_bytes_forward,
        'Init_Win_bytes_backward': init_win_bytes_backward,
        'act_data_pkt_fwd': 0,  # Requires parsing TCP packets
        'min_seg_size_forward': 0,  # Requires parsing TCP packets
        'Active Mean': active_mean,
        'Active Max': active_max,
        'Active Min': active_min,
        'Idle Mean': idle_mean,
        'Idle Max': idle_max,
        'Idle Min': idle_min,
    }
    
    with open(output_csv, 'w') as f:
        header = ",".join(features.keys())
        f.write(header + "\n")
        values = ",".join(map(str, features.values()))
        f.write(values)
        
    print(f"Features saved to {output_csv}")

if __name__ == "__main__":
    # ABSOLUTE PATH
    input_csv = os.path.join("C:\\Users\\narayan\\network_traffic_analysis\\data\\processed", "traffic.csv")
    # ABSOLUTE PATH
    output_csv = os.path.join("C:\\Users\\narayan\\network_traffic_analysis\\data\\processed", "features.csv")
    extract_features(input_csv, output_csv)
