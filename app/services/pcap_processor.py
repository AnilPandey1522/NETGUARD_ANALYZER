import pandas as pd
import numpy as np
import joblib
import os
from collections import Counter
from scapy.all import rdpcap, IP, TCP, UDP

# --- PATH CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__)) 
MODEL_PATH = os.path.join(BASE_DIR, '../../ml_engine/rf_model.pkl')
FEATURES_PATH = os.path.join(BASE_DIR, '../../ml_engine/model_features.pkl')

def extract_features_and_stats(filepath):
    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"Error reading PCAP: {e}")
        return None, None

    total_packets = len(packets)
    if total_packets == 0:
        return None, None
        
    start_time = packets[0].time
    end_time = packets[-1].time
    duration = float(end_time - start_time)
    if duration == 0: duration = 0.000001
        
    pps = total_packets / duration
    
    # --- NEW: DATA FOR GRAPHS ---
    protocol_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
    ip_sources = []
    
    total_len = 0
    
    for pkt in packets:
        if IP in pkt:
            total_len += len(pkt)
            src_ip = pkt[IP].src
            ip_sources.append(src_ip)
            
            # Count Protocols
            if TCP in pkt:
                protocol_counts["TCP"] += 1
            elif UDP in pkt:
                protocol_counts["UDP"] += 1
            else:
                protocol_counts["Other"] += 1

    # Get Top 5 Attacking IPs
    top_ips = Counter(ip_sources).most_common(5)

    # --- PREPARE AI DATA ---
    try:
        model_columns = joblib.load(FEATURES_PATH)
        df = pd.DataFrame(columns=model_columns)
        df.loc[0] = 0 
        if 'Flow Duration' in df.columns: df['Flow Duration'] = duration * 1000000 
        if 'Total Fwd Packets' in df.columns: df['Total Fwd Packets'] = total_packets
        if 'Total Length of Fwd Packets' in df.columns: df['Total Length of Fwd Packets'] = total_len
        df = df.fillna(0)
    except:
        df = None

    stats = {
        "pps": pps,
        "duration": duration,
        "packet_count": total_packets,
        "protocols": protocol_counts,  # Sending this to frontend
        "top_ips": top_ips             # Sending this to frontend
    }
    
    return df, stats

def process_pcap(filepath):
    print(f"AI ENGINE: Analyzing {filepath}...")
    features_df, stats = extract_features_and_stats(filepath)
    
    if stats is None:
        return {"status": "Safe", "details": "File empty."}

    # AI Prediction
    ai_verdict = 0
    if os.path.exists(MODEL_PATH) and features_df is not None:
        try:
            model = joblib.load(MODEL_PATH)
            ai_verdict = model.predict(features_df)[0]
        except:
            pass

    # Decision Logic
    status = "Safe"
    details = f"Normal Traffic ({int(stats['pps'])} pps)"
    
    if ai_verdict == 1:
        status = "Danger"
        details = "AI Detected Malicious Patterns"
    elif stats['pps'] > 1000:
        status = "Danger"
        details = f"High Traffic Anomaly ({int(stats['pps'])} pps)"

    # --- RETURN EVERYTHING TO FLASK ---
    return {
        "status": status,
        "details": details,
        "scan_data": {
            "protocols": stats['protocols'],
            "top_ips": stats['top_ips'],
            "packet_count": stats['packet_count'],
            "duration": round(stats['duration'], 2)
        }
    }