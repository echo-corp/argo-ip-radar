import argparse
from datetime import datetime
import os
import re

# --- Configuration ---
INPUT_DIR = "results"
OUTPUT_DIR = "results"
OUTPUT_PREFIX = "fastest_"
LATENCY_LIMIT = 800.0  # Ignore anything slower than 0.8 second


def positive_float(value):
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def positive_int(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def analyze_ips(input_dir, latency_limit, top):
    ip_data = []
    # Updated Pattern: "IP | Time | Speed"
    pattern = re.compile(r"([\d\.]+)\s*\|\s*([\d\.]+)ms\s*\|\s*([\d\.]+)kbps")

    if not os.path.isdir(input_dir):
        return

    files = [f for f in os.listdir(input_dir) if f.endswith('.txt') and not f.startswith(OUTPUT_PREFIX)]
    if not files: return

    for filename in files:
        with open(os.path.join(input_dir, filename), 'r') as f:
            for line in f:
                match = pattern.search(line)
                if match:
                    ip, lat, speed = match.group(1), float(match.group(2)), float(match.group(3))
                    if lat < latency_limit:
                        ip_data.append({'ip': ip, 'lat': lat, 'speed': speed})

    # SORT LOGIC: Primary sort by Speed (Descending), Secondary by Latency (Ascending)
    ip_data.sort(key=lambda x: (-x['speed'], x['lat']))
    if top is not None:
        ip_data = ip_data[:top]

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    output_file = os.path.join(OUTPUT_DIR, f"{OUTPUT_PREFIX}{datetime.now().strftime('%Y-%m-%d_%H-%M')}.txt")
    with open(output_file, "w") as out:
        for entry in ip_data:
            out.write(f"{entry['ip']} | {entry['lat']:.1f}ms | {entry['speed']:.1f}kbps\n")

    if ip_data:
        print(f"Top IP: {ip_data[0]['ip']} at {ip_data[0]['speed']:.1f} kbps")
    print(f"Sorted results written to {output_file}")


def parse_args():
    parser = argparse.ArgumentParser(description="Sort working IP scan results by speed and latency.")
    parser.add_argument("--latency-limit", type=positive_float, default=LATENCY_LIMIT)
    parser.add_argument("--top", type=positive_int)
    parser.add_argument("--input-dir", default=INPUT_DIR)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    analyze_ips(args.input_dir, args.latency_limit, args.top)
