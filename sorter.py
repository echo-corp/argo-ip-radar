import os
import re

# --- Configuration ---
INPUT_PREFIX = "working_"
OUTPUT_FILE = "fastest_ips.txt"
LATENCY_LIMIT = 800.0  # Ignore anything slower than 0.8 second


def analyze_ips():
    ip_data = []
    # Updated Pattern: "IP | Time | Speed"
    pattern = re.compile(r"([\d\.]+)\s*\|\s*([\d\.]+)ms\s*\|\s*([\d\.]+)kbps")

    files = [f for f in os.listdir('.') if f.startswith(INPUT_PREFIX) and f.endswith('.txt')]
    if not files: return

    for filename in files:
        with open(filename, 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    ip, lat, speed = match.group(1), float(match.group(2)), float(match.group(3))
                    if lat < LATENCY_LIMIT:
                        ip_data.append({'ip': ip, 'lat': lat, 'speed': speed})

    # SORT LOGIC: Primary sort by Speed (Descending), Secondary by Latency (Ascending)
    ip_data.sort(key=lambda x: (-x['speed'], x['lat']))

    with open(OUTPUT_FILE, "w") as out:
        for entry in ip_data:
            out.write(f"{entry['ip']} | {entry['lat']:.1f}ms | {entry['speed']:.1f}kbps\n")

    if ip_data:
        print(f"Top IP: {ip_data[0]['ip']} at {ip_data[0]['speed']:.1f} kbps")


if __name__ == "__main__":
    analyze_ips()
