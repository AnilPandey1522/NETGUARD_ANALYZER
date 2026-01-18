import pandas as pd
import numpy as np
from scapy.all import PcapReader, IP, TCP, UDP # Changed rdpcap to PcapReader

class FeatureExtractor:
    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        self.flows = {}

    def extract(self):
        print(f"Starting extraction for {self.pcap_path}...")
        
        try:
            # Use PcapReader for streaming large files (Low RAM usage)
            # We iterate through the file packet by packet
            with PcapReader(self.pcap_path) as pcap_reader:
                for i, pkt in enumerate(pcap_reader):
                    
                    # Stop after 50,000 packets to prevent waiting hours during testing
                    # In production, you might remove this or increase it.
                    if i > 50000: 
                        break
                        
                    self._process_packet(pkt)
                    
        except Exception as e:
            print(f"Error reading PCAP: {e}")
            return None

        # ... (Rest of the logic remains exactly the same as before) ...
        
        data = []
        for flow_id, flow in self.flows.items():
            # Basic Calculation
            duration = flow['last_seen'] - flow['first_seen']
            flow['Flow Duration'] = duration * 1e6 
            
            # Packet Stats
            if flow['packet_sizes']:
                flow['Total Length of Fwd Packets'] = sum(flow['packet_sizes'])
                flow['Fwd Packet Length Max'] = max(flow['packet_sizes'])
                flow['Fwd Packet Length Min'] = min(flow['packet_sizes'])
                flow['Fwd Packet Length Mean'] = np.mean(flow['packet_sizes'])
            else:
                flow['Total Length of Fwd Packets'] = 0
                flow['Fwd Packet Length Mean'] = 0

            # IAT
            if len(flow['timestamps']) > 1:
                iat = np.diff(flow['timestamps']) * 1e6 
                flow['Flow IAT Mean'] = np.mean(iat)
                flow['Flow IAT Std'] = np.std(iat)
                flow['Flow IAT Max'] = np.max(iat)
                flow['Flow IAT Min'] = np.min(iat)
            else:
                flow['Flow IAT Mean'] = 0
                flow['Flow IAT Std'] = 0
                flow['Flow IAT Max'] = 0
                flow['Flow IAT Min'] = 0

            del flow['timestamps']
            del flow['packet_sizes']
            del flow['first_seen']
            del flow['last_seen']
            
            data.append(flow)

        return pd.DataFrame(data)

    def _process_packet(self, pkt):
        # ... (Keep this method exactly the same as your previous code) ...
        if not pkt.haslayer(IP):
            return

        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = pkt[IP].proto
        length = len(pkt)
        timestamp = float(pkt.time)

        src_port = 0
        dst_port = 0
        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        flow_id = tuple(sorted([(src, src_port), (dst, dst_port)]) + [proto])

        if flow_id not in self.flows:
            self.flows[flow_id] = {
                'Destination Port': dst_port,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'timestamps': [],    
                'packet_sizes': [], 
                'Total Fwd Packets': 0,
                'Total Backward Packets': 0
            }

        flow = self.flows[flow_id]
        flow['last_seen'] = timestamp
        flow['timestamps'].append(timestamp)
        flow['packet_sizes'].append(length)

        if src == flow_id[0][0]:
            flow['Total Fwd Packets'] += 1
        else:
            flow['Total Backward Packets'] += 1