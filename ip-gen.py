import ipaddress
import json
import random

CONFIG_FILE = "subnets.json"
TOTAL_IPS_TO_GENERATE = 10000


def generate_weighted_ips():
    try:
        with open(CONFIG_FILE, 'r') as f:
            subnet_data = json.load(f)
    except FileNotFoundError:
        print("Error: subnets.json not found.")
        return

    subnets = list(subnet_data.keys())
    weights = list(subnet_data.values())

    # Select which subnets to draw from based on their weight
    chosen_subnets = random.choices(subnets, weights=weights, k=TOTAL_IPS_TO_GENERATE)

    with open("ips.txt", "w") as f:
        for cidr in chosen_subnets:
            net = ipaddress.ip_network(cidr)
            # Pick one random IP from the chosen subnet
            random_ip = net[random.randint(0, net.num_addresses - 1)]
            f.write(str(random_ip) + "\n")

    print(f"Generated {TOTAL_IPS_TO_GENERATE} IPs weighted by subnet performance.")


if __name__ == "__main__":
    generate_weighted_ips()
