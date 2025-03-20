#!/usr/bin/env python3
import pyshark
import pandas as pd
import numpy as np
from datetime import datetime
import matplotlib.pyplot as plt
from collections import Counter
import argparse
import sys
from scipy import signal

def analyze_pcap(pcap_file, target_mac, output_csv=None):
    """
    Analyze a pcap file for packets related to a specific IoT device.
    
    Args:
        pcap_file (str): Path to the pcap or pcapng file
        target_mac (str): MAC address of the IoT device to track
        output_csv (str, optional): Path to save packet data as CSV
    """
    print(f"Analyzing {pcap_file} for device with MAC: {target_mac}")
    
    target_mac = target_mac.lower().replace(':', '').replace('-', '')
    
    try:
        capture = pyshark.FileCapture(pcap_file, display_filter=f"wlan")
    except Exception as e:
        print(f"Error opening pcap file: {e}")
        sys.exit(1)

    packet_times = []
    packet_sizes = []
    packet_types = []
  
    print("Processing packets...")
    packet_count = 0
    target_packet_count = 0
    
    try:
        for packet in capture:
            packet_count += 1
            if packet_count % 1000 == 0:
                print(f"Processed {packet_count} packets...")
            
            try:
                if hasattr(packet, 'wlan'):
                    source_mac = packet.wlan.sa.replace(':', '').lower() if hasattr(packet.wlan, 'sa') else ''
                    dest_mac = packet.wlan.da.replace(':', '').lower() if hasattr(packet.wlan, 'da') else ''
                    transmitter_mac = packet.wlan.ta.replace(':', '').lower() if hasattr(packet.wlan, 'ta') else ''
                    receiver_mac = packet.wlan.ra.replace(':', '').lower() if hasattr(packet.wlan, 'ra') else ''
                    
                    if (target_mac in [source_mac, dest_mac, transmitter_mac, receiver_mac]):
                        timestamp = float(packet.sniff_timestamp)
                        packet_size = int(packet.length)
                        frame_type = f"{packet.wlan.fc_type}:{packet.wlan.fc_subtype}" if hasattr(packet.wlan, 'fc_type') and hasattr(packet.wlan, 'fc_subtype') else "unknown"

                        packet_times.append(timestamp)
                        packet_sizes.append(packet_size)
                        packet_types.append(frame_type)
                        target_packet_count += 1
            except AttributeError:
                continue
    except Exception as e:
        print(f"Error processing packets: {e}")
    finally:
        capture.close()
    
    if target_packet_count == 0:
        print(f"No packets found for MAC address {target_mac}")
        return
    
    print(f"Analysis complete. Found {target_packet_count} packets related to target device out of {packet_count} total packets.")
    
    df = pd.DataFrame({
        'timestamp': packet_times,
        'size': packet_sizes,
        'type': packet_types
    })
    
    df = df.sort_values('timestamp')
    df['datetime'] = df['timestamp'].apply(lambda x: datetime.fromtimestamp(x))
    df['time_diff'] = df['timestamp'].diff()

    print("\n=== Packet Statistics ===")
    print(f"Total packets: {len(df)}")
    print(f"Time span: {df['datetime'].min()} to {df['datetime'].max()}")
    print(f"Average packet size: {df['size'].mean():.2f} bytes")
    print(f"Average time between packets: {df['time_diff'].mean():.4f} seconds")

    detect_periodicity(df)

    if output_csv:
        df.to_csv(output_csv, index=False)
        print(f"Packet data saved to {output_csv}")
    
    return df

def detect_periodicity(df):
    """
    Analyze the packet timings to detect periodic patterns.
    
    Args:
        df (DataFrame): DataFrame with packet data
    """
    print("\n=== Periodicity Analysis ===")

    time_diffs = df['time_diff'].dropna().values
    if len(time_diffs) < 10:
        print("Not enough packets to perform periodicity analysis")
        return

    rounded_diffs = np.round(time_diffs, 3)
    counter = Counter(rounded_diffs)
    most_common = counter.most_common(5)
    
    print("Most common time intervals between packets:")
    for interval, count in most_common:
        percentage = (count / len(rounded_diffs)) * 100
        print(f"  {interval:.3f} seconds: {count} occurrences ({percentage:.1f}%)")
    
    dominant_intervals = [(interval, count) for interval, count in most_common 
                         if count / len(rounded_diffs) > 0.1 and interval > 0.001]
    
    if dominant_intervals:
        print("\nPeriodic traffic patterns detected:")
        for interval, count in dominant_intervals:
            print(f"  Interval of {interval:.3f} seconds appears {count} times")
            print(f"  This suggests a periodic traffic pattern of approximately {1/interval:.2f} Hz")
            
            pattern_indices = []
            for i in range(1, len(df)):
                if abs(df['time_diff'].iloc[i] - interval) < 0.01:
                    pattern_indices.append(i)
            
            if pattern_indices:
                pattern_types = Counter(df['type'].iloc[pattern_indices])
                print(f"  Most common frame types in this pattern:")
                for frame_type, type_count in pattern_types.most_common(3):
                    print(f"    {frame_type}: {type_count} packets")
    else:
        print("\nNo strong periodic patterns detected in the traffic")

def analyze_suspicious_patterns(df):
    """
    Analyze the packet data for potential suspicious patterns.
    
    Args:
        df (DataFrame): DataFrame with packet data
    """
    print("\n=== Suspicious Pattern Analysis ===")
    
    df['minute'] = df['datetime'].dt.floor('min')
    traffic_by_minute = df.groupby('minute').size()
    
    avg_packets_per_minute = traffic_by_minute.mean()
    std_packets_per_minute = traffic_by_minute.std()

    high_traffic_minutes = traffic_by_minute[traffic_by_minute > avg_packets_per_minute + 2*std_packets_per_minute]
    
    if not high_traffic_minutes.empty:
        print(f"Detected {len(high_traffic_minutes)} minutes with unusually high traffic:")
        for minute, count in high_traffic_minutes.items():
            print(f"  {minute}: {count} packets (Average: {avg_packets_per_minute:.1f})")
    else:
        print("No unusual traffic bursts detected")

    size_mean = df['size'].mean()
    size_std = df['size'].std()
    unusual_sizes = df[(df['size'] > size_mean + 3*size_std) | (df['size'] < size_mean - 3*size_std)]
    
    if not unusual_sizes.empty:
        print(f"\nDetected {len(unusual_sizes)} packets with unusual sizes:")
        for _, row in unusual_sizes.iloc[:5].iterrows():
            print(f"  {row['datetime']}: {row['size']} bytes (Avg: {size_mean:.1f})")
        if len(unusual_sizes) > 5:
            print(f"  ... and {len(unusual_sizes) - 5} more")
    else:
        print("\nNo packets with unusual sizes detected")

def main():
    parser = argparse.ArgumentParser(description='Analyze pcap files for IoT device traffic patterns')
    parser.add_argument('pcap_file', help='Path to the pcap or pcapng file')
    parser.add_argument('mac_address', help='MAC address of the IoT device to track')
    parser.add_argument('--output', '-o', help='Path to save packet data as CSV')
    args = parser.parse_args()
    
    df = analyze_pcap(args.pcap_file, args.mac_address, args.output)
    
    if df is not None and not df.empty:
        analyze_suspicious_patterns(df)

if __name__ == "__main__":
    main()