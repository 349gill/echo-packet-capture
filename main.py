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
    
    # Normalize MAC address format (remove colons, convert to lowercase)
    target_mac = target_mac.lower().replace(':', '').replace('-', '')
    
    # Read the pcap file - using a display filter to get relevant packets
    # This will include both eth and wlan packets with the target MAC
    try:
        capture = pyshark.FileCapture(pcap_file)
    except Exception as e:
        print(f"Error opening pcap file: {e}")
        sys.exit(1)
    
    # Lists to store packet data
    packet_times = []
    packet_sizes = []
    packet_types = []
    packet_sources = []
    packet_destinations = []
    packet_protocols = []
    
    # Process each packet
    print("Processing packets...")
    packet_count = 0
    target_packet_count = 0
    
    try:
        for packet in capture:
            packet_count += 1
            if packet_count % 1000 == 0:
                print(f"Processed {packet_count} packets...")
            
            try:
                found_match = False
                source_mac = ""
                dest_mac = ""
                
                # Check Ethernet layer
                if hasattr(packet, 'eth'):
                    source_mac = packet.eth.src.replace(':', '').lower() if hasattr(packet.eth, 'src') else ''
                    dest_mac = packet.eth.dst.replace(':', '').lower() if hasattr(packet.eth, 'dst') else ''
                    if target_mac in [source_mac, dest_mac]:
                        found_match = True
                
                # Check WLAN layer if no Ethernet match found
                elif hasattr(packet, 'wlan'):
                    if hasattr(packet.wlan, 'sa'):
                        source_mac = packet.wlan.sa.replace(':', '').lower()
                    if hasattr(packet.wlan, 'da'):
                        dest_mac = packet.wlan.da.replace(':', '').lower()
                    if target_mac in [source_mac, dest_mac]:
                        found_match = True
                    # Check additional WLAN addresses
                    elif hasattr(packet.wlan, 'ta') and packet.wlan.ta.replace(':', '').lower() == target_mac:
                        source_mac = packet.wlan.ta.replace(':', '').lower()
                        found_match = True
                    elif hasattr(packet.wlan, 'ra') and packet.wlan.ra.replace(':', '').lower() == target_mac:
                        dest_mac = packet.wlan.ra.replace(':', '').lower()
                        found_match = True
                
                if found_match:
                    # Get packet details
                    timestamp = float(packet.sniff_timestamp)
                    packet_size = int(packet.length)
                    
                    # Try to identify packet type based on highest layer
                    if hasattr(packet, 'highest_layer'):
                        packet_type = packet.highest_layer
                    else:
                        packet_type = "Unknown"
                    
                    # Get protocol info
                    protocol = packet.layers[0].layer_name.upper()
                    
                    # Store packet details
                    packet_times.append(timestamp)
                    packet_sizes.append(packet_size)
                    packet_types.append(packet_type)
                    packet_sources.append(source_mac)
                    packet_destinations.append(dest_mac)
                    packet_protocols.append(protocol)
                    target_packet_count += 1
            except AttributeError:
                continue
    except Exception as e:
        print(f"Error processing packets: {e}")
    finally:
        capture.close()
    
    if target_packet_count == 0:
        print(f"No packets found for MAC address {target_mac}")
        # Debug: Let's print some of the MAC addresses that were found
        try:
            debug_capture = pyshark.FileCapture(pcap_file)
            print("\nDebugging - Sampling MAC addresses from the first 100 packets:")
            found_eth_macs = set()
            found_wlan_macs = set()
            sample_count = 0
            
            for packet in debug_capture:
                if sample_count >= 100:
                    break
                sample_count += 1
                
                try:
                    # Check Ethernet MACs
                    if hasattr(packet, 'eth'):
                        if hasattr(packet.eth, 'src'):
                            found_eth_macs.add(packet.eth.src)
                        if hasattr(packet.eth, 'dst'):
                            found_eth_macs.add(packet.eth.dst)
                    
                    # Check WLAN MACs
                    if hasattr(packet, 'wlan'):
                        if hasattr(packet.wlan, 'sa'):
                            found_wlan_macs.add(packet.wlan.sa)
                        if hasattr(packet.wlan, 'da'):
                            found_wlan_macs.add(packet.wlan.da)
                        if hasattr(packet.wlan, 'ta'):
                            found_wlan_macs.add(packet.wlan.ta)
                        if hasattr(packet.wlan, 'ra'):
                            found_wlan_macs.add(packet.wlan.ra)
                except:
                    continue
            
            if found_eth_macs:
                print(f"Found {len(found_eth_macs)} unique Ethernet MAC addresses in sample:")
                for mac in list(found_eth_macs)[:10]:  # Show first 10 to avoid overwhelming output
                    print(f"  {mac}")
                if len(found_eth_macs) > 10:
                    print(f"  ...and {len(found_eth_macs) - 10} more")
            
            if found_wlan_macs:
                print(f"Found {len(found_wlan_macs)} unique WLAN MAC addresses in sample:")
                for mac in list(found_wlan_macs)[:10]:  # Show first 10 to avoid overwhelming output
                    print(f"  {mac}")
                if len(found_wlan_macs) > 10:
                    print(f"  ...and {len(found_wlan_macs) - 10} more")
                
            debug_capture.close()
        except Exception as e:
            print(f"Error during debugging: {e}")
            
        return
    
    print(f"Analysis complete. Found {target_packet_count} packets related to target device out of {packet_count} total packets.")
    
    # Create a DataFrame for analysis
    df = pd.DataFrame({
        'timestamp': packet_times,
        'size': packet_sizes,
        'type': packet_types,
        'source': packet_sources,
        'destination': packet_destinations,
        'protocol': packet_protocols
    })
    
    # Sort by timestamp
    df = df.sort_values('timestamp')
    
    # Convert timestamps to datetime for better readability
    df['datetime'] = df['timestamp'].apply(lambda x: datetime.fromtimestamp(x))
    
    # Calculate time differences between consecutive packets (in seconds)
    df['time_diff'] = df['timestamp'].diff()
    
    # Print all packets with relative timing
    print_relative_timing(df)
    
    # Basic statistics
    print("\n=== Packet Statistics ===")
    print(f"Total packets: {len(df)}")
    print(f"Time span: {df['datetime'].min()} to {df['datetime'].max()}")
    print(f"Average packet size: {df['size'].mean():.2f} bytes")
    print(f"Average time between packets: {df['time_diff'].mean():.4f} seconds")
    
    # Protocol distribution
    print("\nProtocol distribution:")
    protocol_counts = df['protocol'].value_counts()
    for protocol, count in protocol_counts.items():
        print(f"  {protocol}: {count} packets ({count/len(df)*100:.1f}%)")
    
    # Most common packet types
    print("\nMost common packet types:")
    type_counts = df['type'].value_counts()
    for packet_type, count in type_counts.items():
        print(f"  {packet_type}: {count} packets ({count/len(df)*100:.1f}%)")
    
    # Detect periodicity
    detect_periodicity(df)
    
    # Analyze traffic patterns
    analyze_traffic_patterns(df, target_mac)
    
    # Save to CSV if requested
    if output_csv:
        df.to_csv(output_csv, index=False)
        print(f"Packet data saved to {output_csv}")
    
    return df

def print_relative_timing(df):
    """
    Print each packet with its relative time in minutes from the first packet.
    
    Args:
        df (DataFrame): DataFrame with packet data (already sorted by timestamp)
    """
    print("\n=== Packet Occurrences with Relative Timing ===")
    
    # Calculate the start time (first packet's timestamp)
    start_time = df['timestamp'].iloc[0]
    
    # Calculate relative time in minutes for each packet
    df['relative_minutes'] = (df['timestamp'] - start_time) / 60.0
    
    # Print each packet with its relative time
    print(f"{'#':>5} | {'Time (min)':>12} | {'Size':>6} | {'Type':>15} | {'Protocol':>8} | {'Source → Destination'}")
    print("-" * 80)
    
    for i, (_, row) in enumerate(df.iterrows()):
        source = format_mac(row['source'])
        dest = format_mac(row['destination'])
        print(f"{i+1:>5} | {row['relative_minutes']:>12.3f} | {row['size']:>6} | {row['type']:>15} | {source} → {dest}")

def detect_periodicity(df):
    """
    Analyze the packet timings to detect periodic patterns.
    
    Args:
        df (DataFrame): DataFrame with packet data
    """
    print("\n=== Periodicity Analysis ===")
    
    # Filter out extreme outliers in time differences
    time_diffs = df['time_diff'].dropna().values
    if len(time_diffs) < 10:
        print("Not enough packets to perform periodicity analysis")
        return
    
    # Round time differences to 3 decimal places to group similar intervals
    rounded_diffs = np.round(time_diffs, 3)
    
    # Count occurrences of each interval
    counter = Counter(rounded_diffs)
    
    # Get the most common intervals
    most_common = counter.most_common(5)
    
    print("Most common time intervals between packets:")
    for interval, count in most_common:
        percentage = (count / len(rounded_diffs)) * 100
        print(f"  {interval:.3f} seconds: {count} occurrences ({percentage:.1f}%)")
    
    # Check if any interval is particularly dominant (indicating periodicity)
    dominant_intervals = [(interval, count) for interval, count in most_common 
                         if count / len(rounded_diffs) > 0.1 and interval > 0.001]
    
    if dominant_intervals:
        print("\nPeriodic traffic patterns detected:")
        for interval, count in dominant_intervals:
            print(f"  Interval of {interval:.3f} seconds appears {count} times")
            print(f"  This suggests a periodic traffic pattern of approximately {1/interval:.2f} Hz")
            
            # Find packets that follow this pattern
            pattern_indices = []
            for i in range(1, len(df)):
                if abs(df['time_diff'].iloc[i] - interval) < 0.01:  # Within 10ms of the interval
                    pattern_indices.append(i)
            
            if pattern_indices:
                pattern_types = Counter(df['type'].iloc[pattern_indices])
                print(f"  Most common packet types in this pattern:")
                for frame_type, type_count in pattern_types.most_common(3):
                    print(f"    {frame_type}: {type_count} packets")
    else:
        print("\nNo strong periodic patterns detected in the traffic")

def analyze_traffic_patterns(df, target_mac):
    """
    Analyze the traffic patterns for potential anomalies or suspicious behavior.
    
    Args:
        df (DataFrame): DataFrame with packet data
        target_mac (str): MAC address of the IoT device
    """
    print("\n=== Traffic Pattern Analysis ===")
    
    # Check for bursts of traffic
    df['minute'] = df['datetime'].dt.floor('min')
    traffic_by_minute = df.groupby('minute').size()
    
    # Skip if we don't have enough data
    if len(traffic_by_minute) < 3:
        print("Not enough time data to analyze traffic patterns")
        return
    
    avg_packets_per_minute = traffic_by_minute.mean()
    std_packets_per_minute = traffic_by_minute.std()
    
    # Identify minutes with unusually high traffic
    high_traffic_minutes = traffic_by_minute[traffic_by_minute > avg_packets_per_minute + 2*std_packets_per_minute]
    
    if not high_traffic_minutes.empty:
        print(f"Detected {len(high_traffic_minutes)} minutes with unusually high traffic:")
        for minute, count in high_traffic_minutes.items():
            print(f"  {minute}: {count} packets (Average: {avg_packets_per_minute:.1f})")
    else:
        print("No unusual traffic bursts detected")
    
    # Analyze packet sizes
    print("\nPacket size distribution:")
    size_stats = df['size'].describe()
    print(f"  Min: {size_stats['min']:.0f} bytes")
    print(f"  25th percentile: {size_stats['25%']:.0f} bytes")
    print(f"  Median: {size_stats['50%']:.0f} bytes")
    print(f"  75th percentile: {size_stats['75%']:.0f} bytes")
    print(f"  Max: {size_stats['max']:.0f} bytes")
    
    # Check for unusual packet sizes
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
    
    # Analyze communication patterns
    print("\nCommunication patterns:")
    
    # Normalize mac address format for comparison
    target_mac = target_mac.lower().replace(':', '').replace('-', '')
    
    # Who is the device talking to?
    outgoing_df = df[df['source'] == target_mac]
    if not outgoing_df.empty:
        dest_counts = outgoing_df['destination'].value_counts()
        print(f"Top destinations that device talks to:")
        for dest, count in dest_counts.head(5).items():
            print(f"  {format_mac(dest)}: {count} packets")
    
    # Who is talking to the device?
    incoming_df = df[df['destination'] == target_mac]
    if not incoming_df.empty:
        source_counts = incoming_df['source'].value_counts()
        print(f"Top sources talking to the device:")
        for src, count in source_counts.head(5).items():
            print(f"  {format_mac(src)}: {count} packets")

def format_mac(mac_str):
    """Format a MAC address with colons for readability"""
    # Add colons every 2 characters
    mac = ':'.join(mac_str[i:i+2] for i in range(0, len(mac_str), 2))
    return mac

def main():
    parser = argparse.ArgumentParser(description='Analyze pcap files for IoT device traffic patterns')
    parser.add_argument('pcap_file', help='Path to the pcap or pcapng file')
    parser.add_argument('mac_address', help='MAC address of the IoT device to track')
    parser.add_argument('--output', '-o', help='Path to save packet data as CSV')
    args = parser.parse_args()
    
    df = analyze_pcap(args.pcap_file, args.mac_address, args.output)

if __name__ == "__main__":
    main()