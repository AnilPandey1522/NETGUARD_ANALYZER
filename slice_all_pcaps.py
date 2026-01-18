from scapy.all import PcapReader, wrpcap
import os

# --- CONFIGURATION ---
SOURCE_DIR = r"D:\Downloads\DataSets"
OUTPUT_DIR = os.getcwd()  # Saves in the current folder

# List of files we want to process
FILES_TO_PROCESS = [
    "Monday-WorkingHours.pcap",
    "Tuesday-WorkingHours.pcap",
    "Wednesday-workingHours.pcap", 
    "Thursday-WorkingHours.pcap",
    "Friday-WorkingHours.pcap"
]

def slice_all():
    print(f"--- STARTING BATCH SLICER ---")
    print(f"Looking in: {SOURCE_DIR}")
    
    for filename in FILES_TO_PROCESS:
        source_path = os.path.join(SOURCE_DIR, filename)
        output_filename = f"sample_{filename}"
        output_path = os.path.join(OUTPUT_DIR, output_filename)
        
        print(f"\nProcessing: {filename}...")
        
        if not os.path.exists(source_path):
            print(f"   [!] File not found, skipping: {filename}")
            continue

        try:
            packets = []
            count = 0
            skip_count = 0
            target_skip = 25000  # Skip first 25k to get deep into the traffic
            sample_size = 3000   # Capture 3k packets
            
            # Read the huge file stream
            with PcapReader(source_path) as reader:
                for pkt in reader:
                    # 1. Skip initial packets
                    if skip_count < target_skip:
                        skip_count += 1
                        continue
                    
                    # 2. Capture sample
                    packets.append(pkt)
                    count += 1
                    if count >= sample_size:
                        break
            
            # Save the small file
            if count > 0:
                wrpcap(output_path, packets)
                print(f"   [+] Success! Saved {output_filename} ({count} packets)")
            else:
                print("   [!] Warning: File was too short, no packets captured.")

        except Exception as e:
            print(f"   [!] Error processing {filename}: {e}")

    print("\n--- BATCH COMPLETE ---")
    print("You can now upload any 'sample_...' file to NetGuard.")

if __name__ == "__main__":
    slice_all()