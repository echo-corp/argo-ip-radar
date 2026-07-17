import argparse
import ipaddress
import json
import random

CONFIG_FILE = "subnets.json"
TOTAL_IPS_TO_GENERATE = 10000
DEFAULT_OUTPUT_FILE = "ips.txt"


def positive_int(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def get_subnet_weight(value):
    if isinstance(value, dict):
        return float(value.get("weight", 0.1))
    return float(value)


def generate_weighted_ips(count, output_file):
    try:
        with open(CONFIG_FILE, 'r') as f:
            subnet_data = json.load(f)
    except FileNotFoundError:
        print("Error: subnets.json not found.")
        return

    subnets = list(subnet_data.keys())
    weights = [get_subnet_weight(value) for value in subnet_data.values()]

    # Select which subnets to draw from based on their weight
    chosen_subnets = random.choices(subnets, weights=weights, k=count)

    with open(output_file, "w") as f:
        for cidr in chosen_subnets:
            net = ipaddress.ip_network(cidr)
            # Pick one random IP from the chosen subnet
            random_ip = net[random.randint(0, net.num_addresses - 1)]
            f.write(str(random_ip) + "\n")

    print(f"Generated {count} IPs weighted by subnet performance into {output_file}.")


def parse_args():
    parser = argparse.ArgumentParser(description="Generate weighted Cloudflare IP candidates.")
    parser.add_argument("--count", type=positive_int, default=TOTAL_IPS_TO_GENERATE)
    parser.add_argument("--output", default=DEFAULT_OUTPUT_FILE)
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    generate_weighted_ips(args.count, args.output)
