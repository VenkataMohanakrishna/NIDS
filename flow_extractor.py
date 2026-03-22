import pyshark
import pandas as pd
import numpy as np
import os
from collections import defaultdict
from typing import DefaultDict, List, TypedDict, Any, Tuple

class FlowFeatures(TypedDict):
    times: List[float]
    lengths: List[int]
    fwd_lengths: List[int]
    bwd_lengths: List[int]
    fwd_packets: int
    bwd_packets: int
    fin_count: int
    psh_count: int
    ack_count: int

import sys

output_file = "live_flows_basic.csv"
capture_duration = 5

if len(sys.argv) > 1:
    pcap_file = sys.argv[1]
    print(f"Starting PCAP network capture from {pcap_file}...")
    capture = pyshark.FileCapture(pcap_file)
    capture.load_packets()
    packet_list = [pkt for pkt in capture]
    print(f"Captured {len(packet_list)} packets from PCAP.")
else:
    print(f"Starting LIVE network capture for {capture_duration} seconds...")
    try:
        capture = pyshark.LiveCapture(interface='Wi-Fi')
        capture.sniff(timeout=capture_duration)
    except Exception:
        capture = pyshark.LiveCapture()
        capture.sniff(timeout=capture_duration)

    packet_list = getattr(capture, '_packets', [])
    print(f"Captured {len(packet_list)} packets in {capture_duration} seconds.")

def new_flow() -> FlowFeatures:
    return {
        "times": [],
        "lengths": [],
        "fwd_lengths": [],
        "bwd_lengths": [],
        "fwd_packets": 0,
        "bwd_packets": 0,
        "fin_count": 0,
        "psh_count": 0,
        "ack_count": 0
    }

flows: dict[Tuple[Any, ...], FlowFeatures] = {}

# ---------------------------------------------------
# Packet collection
# ---------------------------------------------------

for pkt in packet_list:

    try:
        if 'IP' in pkt and pkt.transport_layer:

            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            proto = pkt.transport_layer

            src_port = pkt[pkt.transport_layer].srcport
            dst_port = pkt[pkt.transport_layer].dstport

            pkt_len = int(pkt.length)
            timestamp = float(pkt.sniff_timestamp)

            endpoint1 = (str(src_ip), int(src_port))
            endpoint2 = (str(dst_ip), int(dst_port))

            endpoints = [endpoint1, endpoint2]
            endpoints.sort()
            flow_id = tuple(endpoints) + (str(proto),)

            if flow_id not in flows:
                flows[flow_id] = new_flow()
            flow = flows[flow_id]

            flow["times"].append(timestamp)
            flow["lengths"].append(pkt_len)

            if endpoint1 <= endpoint2:
                flow["fwd_packets"] += 1
                flow["fwd_lengths"].append(pkt_len)
            else:
                flow["bwd_packets"] += 1
                flow["bwd_lengths"].append(pkt_len)

            if proto == "TCP":

                flags = int(pkt.tcp.flags, 16)

                if flags & 0x01:
                    flow["fin_count"] += 1

                if flags & 0x08:
                    flow["psh_count"] += 1

                if flags & 0x10:
                    flow["ack_count"] += 1

    except:
        continue

print("Total flows detected:", len(flows))

rows = []

for flow_id, flow in flows.items():

    times = sorted(flow["times"])
    lengths = flow["lengths"]

    fwd_lengths = flow["fwd_lengths"]
    bwd_lengths = flow["bwd_lengths"]

    start_time = min(times)
    end_time = max(times)

    duration = end_time - start_time

    total_packets = len(lengths)
    total_bytes = sum(lengths)

    pkt_mean = np.mean(lengths)
    pkt_std = np.std(lengths)
    pkt_max = np.max(lengths)
    pkt_min = np.min(lengths)

    # Inter-arrival times
    if len(times) > 1:
        iat = np.diff(times)
        iat_mean = np.mean(iat)
        iat_std = np.std(iat)
        iat_max = np.max(iat)
        iat_min = np.min(iat)
    else:
        iat_mean = iat_std = iat_max = iat_min = 0

    # Active / Idle calculation
    active_times = []
    idle_times = []

    threshold = 1.0

    last_time = times[0]
    active_start = last_time

    for i in range(1, len(times)):
        t = times[i]

        gap = t - last_time

        if gap > threshold:
            active_times.append(float(last_time) - float(active_start))
            idle_times.append(float(gap))
            active_start = t

        last_time = t

    active_times.append(float(last_time) - float(active_start))

    if active_times:
        active_mean = np.mean(active_times)
        active_max = np.max(active_times)
        active_min = np.min(active_times)
    else:
        active_mean = active_max = active_min = 0

    if idle_times:
        idle_mean = np.mean(idle_times)
        idle_max = np.max(idle_times)
        idle_min = np.min(idle_times)
    else:
        idle_mean = idle_max = idle_min = 0

    if duration > 0:
        bytes_per_sec = float(total_bytes) / float(duration)
        packets_per_sec = float(total_packets) / float(duration)
    else:
        bytes_per_sec = packets_per_sec = 0

    row = {

        "Flow Duration": duration,

        "Total Fwd Packets": flow["fwd_packets"],
        "Total Length of Fwd Packets": sum(fwd_lengths),

        "Total Backward Packets": flow["bwd_packets"],
        "Total Length of Bwd Packets": sum(bwd_lengths),

        "Fwd Packet Length Max": max(fwd_lengths) if fwd_lengths else 0,
        "Fwd Packet Length Min": min(fwd_lengths) if fwd_lengths else 0,
        "Fwd Packet Length Mean": np.mean(fwd_lengths) if fwd_lengths else 0,
        "Fwd Packet Length Std": np.std(fwd_lengths) if fwd_lengths else 0,

        "Bwd Packet Length Max": max(bwd_lengths) if bwd_lengths else 0,
        "Bwd Packet Length Min": min(bwd_lengths) if bwd_lengths else 0,
        "Bwd Packet Length Mean": np.mean(bwd_lengths) if bwd_lengths else 0,
        "Bwd Packet Length Std": np.std(bwd_lengths) if bwd_lengths else 0,

        "Packet Length Mean": pkt_mean,
        "Packet Length Std": pkt_std,
        "Max Packet Length": pkt_max,
        "Min Packet Length": pkt_min,

        "Flow Bytes/s": bytes_per_sec,
        "Flow Packets/s": packets_per_sec,

        "Flow IAT Mean": iat_mean,
        "Flow IAT Std": iat_std,
        "Flow IAT Max": iat_max,
        "Flow IAT Min": iat_min,

        "FIN Flag Count": flow["fin_count"],
        "PSH Flag Count": flow["psh_count"],
        "ACK Flag Count": flow["ack_count"],

        "Active Mean": active_mean,
        "Active Max": active_max,
        "Active Min": active_min,

        "Idle Mean": idle_mean,
        "Idle Max": idle_max,
        "Idle Min": idle_min
    }

    rows.append(row)

df = pd.DataFrame(rows)

if os.path.exists(output_file):
    try:
        os.remove(output_file)
    except PermissionError:
        print("Close live_flows_basic.csv and run again.")
        exit()

df.to_csv(output_file, index=False)

print("Flow feature file created:", output_file)
print("Total flows exported:", len(df))