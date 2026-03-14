import subprocess
import time
import sys

print("===================================")
print(" Deep Learning NIDS Monitoring ")
print("===================================\n")

capture_duration = 30
interface = "Wi-Fi"

python_exec = sys.executable

while True:

    print("Starting packet capture...")

    subprocess.run([
        "tshark",
        "-i", interface,
        "-a", f"duration:{capture_duration}",
        "-w", "test_live.pcap"
    ])

    print("Packet capture finished")

    print("Extracting flows...")
    subprocess.run([python_exec, "flow_extractor.py"])

    print("Running intrusion detection...")
    subprocess.run([python_exec, "predict_live.py"])

    print("\nMonitoring cycle complete")
    print("Waiting for next capture...\n")

    time.sleep(5)