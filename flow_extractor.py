import pyshark
import pandas as pd
import numpy as np
import os
import sys
import json
import joblib
import asyncio
import subprocess
from collections import defaultdict
from typing import List, Dict, Any, Tuple

# Configuration
OUTPUT_FILE = "live_flows_basic.csv"
CAPTURE_DURATION = 5
FEATURES_JSON = "features.json"
MAX_PACKETS = 5000

def get_feature_columns():
    """Load the required feature columns from features.json or nids_scaler.pkl"""
    if os.path.exists(FEATURES_JSON):
        with open(FEATURES_JSON, 'r') as f:
            return json.load(f)
    if os.path.exists("nids_scaler.pkl"):
        scaler = joblib.load("nids_scaler.pkl")
        return list(scaler.feature_names_in_)
    return []

FEATURE_COLUMNS = get_feature_columns()

class Flow:
    def __init__(self, first_pkt):
        self.start_time = float(first_pkt.sniff_timestamp)
        self.last_time = self.start_time
        
        # 5-tuple
        self.src_ip = first_pkt.ip.src
        self.src_port = int(first_pkt[first_pkt.transport_layer].srcport)
        self.dst_ip = first_pkt.ip.dst
        self.dst_port = int(first_pkt[first_pkt.transport_layer].dstport)
        self.protocol = first_pkt.transport_layer
        
        # Flow data
        self.fwd_packets = []
        self.bwd_packets = []
        
        self.fwd_iat = []
        self.bwd_iat = []
        self.flow_iat = []
        
        self.last_fwd_time = self.start_time
        self.last_bwd_time = None
        
        # TCP specific
        self.init_win_fwd = 0
        self.init_win_bwd = 0
        if self.protocol == 'TCP':
            self.init_win_fwd = int(first_pkt.tcp.window_size)
            
        self.add_packet(first_pkt)

    def add_packet(self, pkt):
        timestamp = float(pkt.sniff_timestamp)
        pkt_len = int(pkt.length)
        
        # Direction handling
        is_fwd = (pkt.ip.src == self.src_ip and 
                  int(pkt[pkt.transport_layer].srcport) == self.src_port)
        
        # Flow IAT
        self.flow_iat.append((timestamp - self.last_time) * 1e6)
        self.last_time = timestamp
        
        if is_fwd:
            if len(self.fwd_packets) > 0:
                self.fwd_iat.append((timestamp - self.last_fwd_time) * 1e6)
            self.last_fwd_time = timestamp
            self.fwd_packets.append(pkt)
        else:
            if self.last_bwd_time is not None:
                self.bwd_iat.append((timestamp - self.last_bwd_time) * 1e6)
            elif self.protocol == 'TCP' and self.init_win_bwd == 0:
                self.init_win_bwd = int(pkt.tcp.window_size)
            self.last_bwd_time = timestamp
            self.bwd_packets.append(pkt)

    def extract_features(self) -> Dict[str, Any]:
        fwd_lens = [int(p.length) for p in self.fwd_packets]
        bwd_lens = [int(p.length) for p in self.bwd_packets]
        all_lens = fwd_lens + bwd_lens
        
        duration = (self.last_time - self.start_time) * 1e6
        
        # Basic features
        res = {
            "Destination Port": self.dst_port,
            "Flow Duration": duration,
            "Total Fwd Packets": len(self.fwd_packets),
            "Total Backward Packets": len(self.bwd_packets),
            "Total Length of Fwd Packets": sum(fwd_lens),
            "Total Length of Bwd Packets": sum(bwd_lens),
        }
        
        # Fwd Length Stats
        res["Fwd Packet Length Max"] = np.max(fwd_lens) if fwd_lens else 0
        res["Fwd Packet Length Min"] = np.min(fwd_lens) if fwd_lens else 0
        res["Fwd Packet Length Mean"] = np.mean(fwd_lens) if fwd_lens else 0
        res["Fwd Packet Length Std"] = np.std(fwd_lens) if len(fwd_lens) > 1 else 0
        
        # Bwd Length Stats
        res["Bwd Packet Length Max"] = np.max(bwd_lens) if bwd_lens else 0
        res["Bwd Packet Length Min"] = np.min(bwd_lens) if bwd_lens else 0
        res["Bwd Packet Length Mean"] = np.mean(bwd_lens) if bwd_lens else 0
        res["Bwd Packet Length Std"] = np.std(bwd_lens) if len(bwd_lens) > 1 else 0
        
        # Rates
        res["Flow Bytes/s"] = (sum(all_lens) / (duration / 1e6)) if duration > 0 else 0
        res["Flow Packets/s"] = (len(all_lens) / (duration / 1e6)) if duration > 0 else 0
        
        # Flow IAT
        res["Flow IAT Mean"] = np.mean(self.flow_iat[1:]) if len(self.flow_iat) > 1 else 0
        res["Flow IAT Std"] = np.std(self.flow_iat[1:]) if len(self.flow_iat) > 2 else 0
        res["Flow IAT Max"] = np.max(self.flow_iat[1:]) if len(self.flow_iat) > 1 else 0
        res["Flow IAT Min"] = np.min(self.flow_iat[1:]) if len(self.flow_iat) > 1 else 0
        
        # Fwd IAT
        res["Fwd IAT Total"] = sum(self.fwd_iat)
        res["Fwd IAT Mean"] = np.mean(self.fwd_iat) if self.fwd_iat else 0
        res["Fwd IAT Std"] = np.std(self.fwd_iat) if len(self.fwd_iat) > 1 else 0
        res["Fwd IAT Max"] = np.max(self.fwd_iat) if self.fwd_iat else 0
        res["Fwd IAT Min"] = np.min(self.fwd_iat) if self.fwd_iat else 0
        
        # Bwd IAT
        res["Bwd IAT Total"] = sum(self.bwd_iat)
        res["Bwd IAT Mean"] = np.mean(self.bwd_iat) if self.bwd_iat else 0
        res["Bwd IAT Std"] = np.std(self.bwd_iat) if len(self.bwd_iat) > 1 else 0
        res["Bwd IAT Max"] = np.max(self.bwd_iat) if self.bwd_iat else 0
        res["Bwd IAT Min"] = np.min(self.bwd_iat) if self.bwd_iat else 0
        
        # Header Lengths
        fwd_header_len = 0
        for p in self.fwd_packets:
            fwd_header_len += int(p.ip.hdr_len)
            if self.protocol == 'TCP': fwd_header_len += int(p.tcp.hdr_len)
            elif self.protocol == 'UDP': fwd_header_len += 8
        
        bwd_header_len = 0
        for p in self.bwd_packets:
            bwd_header_len += int(p.ip.hdr_len)
            if self.protocol == 'TCP': bwd_header_len += int(p.tcp.hdr_len)
            elif self.protocol == 'UDP': bwd_header_len += 8
            
        res["Fwd Header Length"] = fwd_header_len
        res["Bwd Header Length"] = bwd_header_len
        
        # Packet Rates
        res["Fwd Packets/s"] = (len(self.fwd_packets) / (duration / 1e6)) if duration > 0 else 0
        res["Bwd Packets/s"] = (len(self.bwd_packets) / (duration / 1e6)) if duration > 0 else 0
        
        # Packet Length Stats
        res["Min Packet Length"] = np.min(all_lens) if all_lens else 0
        res["Max Packet Length"] = np.max(all_lens) if all_lens else 0
        res["Packet Length Mean"] = np.mean(all_lens) if all_lens else 0
        res["Packet Length Std"] = np.std(all_lens) if len(all_lens) > 1 else 0
        res["Packet Length Variance"] = np.var(all_lens) if len(all_lens) > 1 else 0
        
        # Flags (TCP only)
        fin_cnt = psh_cnt = ack_cnt = 0
        if self.protocol == 'TCP':
            for p in self.fwd_packets + self.bwd_packets:
                f = int(p.tcp.flags, 16)
                if f & 0x01: fin_cnt += 1
                if f & 0x08: psh_cnt += 1
                if f & 0x10: ack_cnt += 1
        
        res["FIN Flag Count"] = fin_cnt
        res["PSH Flag Count"] = psh_cnt
        res["ACK Flag Count"] = ack_cnt
        
        # Misc
        res["Average Packet Size"] = (sum(all_lens) / len(all_lens)) if all_lens else 0
        res["Subflow Fwd Bytes"] = res["Total Length of Fwd Packets"]
        res["Init_Win_bytes_forward"] = self.init_win_fwd
        res["Init_Win_bytes_backward"] = self.init_win_bwd
        
        # act_data_pkt_fwd
        act_data_fwd = 0
        if self.protocol == 'TCP':
            for p in self.fwd_packets:
                if int(p.tcp.len) > 0: act_data_fwd += 1
        res["act_data_pkt_fwd"] = act_data_fwd
        
        # min_seg_size_forward
        min_seg_fwd = 0
        if self.protocol == 'TCP' and self.fwd_packets:
            min_seg_fwd = min([int(p.tcp.hdr_len) for p in self.fwd_packets])
        res["min_seg_size_forward"] = min_seg_fwd
        
        # Active/Idle
        # Using 5s threshold for Idle as per CICIDS2017
        active_times = []
        idle_times = []
        
        if len(self.flow_iat) > 1:
            curr_active = 0
            for iat in self.flow_iat[1:]:
                if iat > 5e6: # 5 seconds
                    if curr_active > 0: active_times.append(curr_active)
                    idle_times.append(iat)
                    curr_active = 0
                else:
                    curr_active += iat
            if curr_active > 0: active_times.append(curr_active)
        
        res["Active Mean"] = np.mean(active_times) if active_times else 0
        res["Active Max"] = np.max(active_times) if active_times else 0
        res["Active Min"] = np.min(active_times) if active_times else 0
        res["Idle Mean"] = np.mean(idle_times) if idle_times else 0
        res["Idle Max"] = np.max(idle_times) if idle_times else 0
        res["Idle Min"] = np.min(idle_times) if idle_times else 0
        
        return res

def process_pcaps():
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
        print(f"Reading from PCAP: {pcap_file}")
        capture = pyshark.FileCapture(pcap_file)
    else:
        print(f"Starting LIVE capture for {CAPTURE_DURATION}s...")
        pcap_file = "live_capture.pcap"
        try:
            # Capture using tshark directly to avoid pyshark LiveCapture hangs
            subprocess.run(["tshark", "-i", "Wi-Fi", "-a", f"duration:{CAPTURE_DURATION}", "-w", pcap_file], check=True, capture_output=True)
            capture = pyshark.FileCapture(pcap_file)
        except Exception as e:
            print(f"Failed with Wi-Fi interface ({e}), trying default...")
            try:
                subprocess.run(["tshark", "-a", f"duration:{CAPTURE_DURATION}", "-w", pcap_file], check=True, capture_output=True)
                capture = pyshark.FileCapture(pcap_file)
            except Exception as e2:
                print(f"Failed default capture: {e2}")
                return
    
    flows = {}
    
    count = 0
    for pkt in capture:
        if count >= MAX_PACKETS:
            print(f"Reached limit of {MAX_PACKETS} packets. Stopping extraction.")
            break
            
        try:
            if 'IP' not in pkt or not pkt.transport_layer:
                continue
            
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
            src_port = int(pkt[pkt.transport_layer].srcport)
            dst_port = int(pkt[pkt.transport_layer].dstport)
            proto = pkt.transport_layer
            
            # Bidirectional 5-tuple
            id1 = (src_ip, src_port, dst_ip, dst_port, proto)
            id2 = (dst_ip, dst_port, src_ip, src_port, proto)
            
            if id1 in flows:
                flows[id1].add_packet(pkt)
            elif id2 in flows:
                flows[id2].add_packet(pkt)
            else:
                flows[id1] = Flow(pkt)
            
            count += 1
            if count % 1000 == 0:
                print(f"Processed {count} packets...")
                
        except Exception as e:
            continue
            
    print(f"Total packets processed: {count}")
    print(f"Unique flows detected: {len(flows)}")
    
    rows = []
    for f_id, flow_obj in flows.items():
        features = flow_obj.extract_features()
        
        # Alignment and validation
        aligned_row = {}
        for col in FEATURE_COLUMNS:
            val = features.get(col, 0)
            if np.isnan(val) or np.isinf(val):
                val = 0
            aligned_row[col] = val
        
        rows.append(aligned_row)
        
    df = pd.DataFrame(rows)
    
    # Final ordering check
    if FEATURE_COLUMNS:
        for col in FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = 0
        df = df[FEATURE_COLUMNS]
    
    print("\nFeature extraction complete.")
    print("DataFrame shape:", df.shape)
    if not df.empty:
        print("Sample row (first 5 features):")
        print(df.iloc[0, :5])
    
    df.to_csv(OUTPUT_FILE, index=False)
    print(f"\nSaved to {OUTPUT_FILE}")

if __name__ == "__main__":
    process_pcaps()