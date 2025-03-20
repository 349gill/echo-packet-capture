import pyshark
import csv

pcap_file = "captures/Zarin’s MacBook Air_ch161_2025-03-15_16.18.16.678.pcap"
csv_file = "captures/capture.csv"
wlan_filter = "wlan.addr == A4:08:01:CD:6D:9C"

capture = pyshark.FileCapture(pcap_file, display_filter=wlan_filter)

first_packet = next(iter(capture), None)
start_time = float(first_packet.sniff_timestamp) if first_packet else 0

with open(csv_file, "w", newline="", encoding="utf-8") as file:
    writer = csv.writer(file)
    # Source Address, Destination Address, Time, Size

    for packet in capture:
        try:
            if hasattr(packet, "wlan"):
                src = packet.wlan.sa if hasattr(packet.wlan, "sa") else "N/A"
                dst = packet.wlan.da if hasattr(packet.wlan, "da") else "N/A"
                time = float(packet.sniff_timestamp) - start_time
                size = int(packet.length)
                writer.writerow([src, dst, round(time, 2), size])

        except Exception as e:
            print(f"Skipping packet due to error: {e}")