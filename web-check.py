import ipaddress
import argparse
import base64
import hashlib
import json
import os
import signal
import shutil
import socket
import ssl
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import datetime
from urllib.parse import parse_qs, unquote, urlparse

# --- Configuration ---
IPS_FILE = "ips.txt"
SUBNETS_FILE = "subnets.json"  # Your new "brain" file
RESULTS_DIR = "results"
PROGRESS_FILE = ".session_progress.txt"
ID_FILE = ".file_id.txt"
DEFAULT_HOST = "cloudflare.com"
DEFAULT_PATH = "/cdn-cgi/trace"
MAX_THREADS = 10
RECENT_RESULTS_LIMIT = 12
TOP_RESULTS_LIMIT = 3
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MIN_SUBNET_WEIGHT = 0.1
MAX_SUBNET_WEIGHT = 10.0
BASE_FAIL_PENALTY = 0.9
HIGH_FAIL_RATE_THRESHOLD = 0.7
HIGH_FAIL_RATE_MIN_SAMPLES = 5

# --- Colors ---
GREEN, RED, CYAN, YELLOW, PINK, RESET = "\033[92m", "\033[91m", "\033[96m", "\033[93m", "\033[95m", "\033[0m"
BOLD, DIM, CLEAR_SCREEN, CURSOR_HOME, HIDE_CURSOR, SHOW_CURSOR = (
    "\033[1m",
    "\033[2m",
    "\033[2J",
    "\033[H",
    "\033[?25l",
    "\033[?25h",
)

# --- Global State ---
stop_requested = False
lock = threading.RLock()
checked_count = 0
total_ips = 0
success_count = 0
block_count = 0
latency_total = 0.0
speed_total = 0.0
latencies = deque(maxlen=15)
recent_results = deque(maxlen=RECENT_RESULTS_LIMIT)
top_results = []
# Buffer for subnet stats to avoid constant disk writes
subnet_stats = {}
parsed_subnets = []
scanner_settings = {}
runtime_settings = {
    "threads": MAX_THREADS,
    "timeout_min": 0.6,
    "timeout_max": 2.5,
    "recent": RECENT_RESULTS_LIMIT,
    "no_color": False,
}
scan_started_at = None
scan_output_path = None
scan_summary_path = None

shared_context = None


def positive_int(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def positive_float(value):
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than 0")
    return parsed


def disable_colors():
    global GREEN, RED, CYAN, YELLOW, PINK, RESET, BOLD, DIM, CLEAR_SCREEN, CURSOR_HOME, HIDE_CURSOR, SHOW_CURSOR
    GREEN = RED = CYAN = YELLOW = PINK = RESET = ""
    BOLD = DIM = CLEAR_SCREEN = CURSOR_HOME = HIDE_CURSOR = SHOW_CURSOR = ""


def parse_vless_config(raw_config):
    parsed = urlparse(raw_config.strip())
    if parsed.scheme.lower() != "vless":
        raise ValueError("config must start with vless://")

    query = parse_qs(parsed.query)
    path = query.get("path", [DEFAULT_PATH])[0]
    if not path.startswith("/"):
        path = "/" + path

    host = query.get("host", [None])[0] or parsed.hostname
    sni = query.get("sni", [None])[0] or host
    alpn = []
    for item in query.get("alpn", []):
        alpn.extend(part for part in unquote(item).split(",") if part)
    if query.get("type", [""])[0].lower() == "ws" and "http/1.1" in alpn:
        # Classic WebSocket Upgrade is an HTTP/1.1 request. Offering h2 first can
        # make Cloudflare negotiate HTTP/2, which would turn a good IP into a false negative.
        alpn = ["http/1.1"]

    return {
        "host": host,
        "sni": sni,
        "path": path,
        "alpn": alpn,
        "insecure": query.get("insecure", query.get("allowInsecure", ["1"]))[0] in {"1", "true", "True"},
    }


def build_settings(args):
    settings = {
        "host": DEFAULT_HOST,
        "sni": DEFAULT_HOST,
        "path": DEFAULT_PATH,
        "alpn": [],
        "insecure": True,
    }

    raw_config = args.config or os.environ.get("ARGO_IP_RADAR_CONFIG")
    if raw_config:
        settings.update(parse_vless_config(raw_config))

    if args.host:
        settings["host"] = args.host
    if args.sni:
        settings["sni"] = args.sni
    if args.path:
        settings["path"] = args.path if args.path.startswith("/") else "/" + args.path
    if args.alpn:
        settings["alpn"] = [part for part in args.alpn.split(",") if part]
    if args.insecure:
        settings["insecure"] = True

    if not settings["host"]:
        raise ValueError("missing WebSocket Host")
    if not settings["sni"]:
        settings["sni"] = settings["host"]
    return settings


def create_tls_context(settings):
    context = ssl.create_default_context()
    if settings["insecure"]:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if settings["alpn"]:
        context.set_alpn_protocols(settings["alpn"])
    return context


def parse_http_response_head(resp_data):
    head = resp_data.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1", errors="replace")
    lines = head.split("\r\n")
    status_line = lines[0] if lines else ""
    parts = status_line.split(" ", 2)
    status_code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    headers = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        headers[key.strip().lower()] = value.strip()
    return status_code, headers


def make_ws_upgrade_request(settings, ws_key):
    return (
        f"GET {settings['path']} HTTP/1.1\r\n"
        f"Host: {settings['host']}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: Mozilla/5.0 AppleWebKit/537.36 Chrome/126 Safari/537.36\r\n"
        f"Origin: https://{settings['host']}\r\n"
        "\r\n"
    )


def validate_ws_upgrade(resp_data, ws_key):
    if b"\r\n\r\n" not in resp_data:
        return False, "no-http-head"

    status_code, headers = parse_http_response_head(resp_data)
    if status_code != 101:
        return False, f"http-{status_code or 'bad'}"

    upgrade = headers.get("upgrade", "").lower()
    connection = headers.get("connection", "").lower()
    accept = headers.get("sec-websocket-accept", "")
    expected_accept = base64.b64encode(hashlib.sha1((ws_key + WS_GUID).encode()).digest()).decode()
    if upgrade != "websocket" or "upgrade" not in connection or accept != expected_accept:
        return False, "bad-ws-upgrade"
    return True, "ws-101"


def clamp_subnet_weight(weight):
    return round(max(MIN_SUBNET_WEIGHT, min(MAX_SUBNET_WEIGHT, weight)), 3)


def normalize_subnet_stats(raw_data):
    """Accepts old float weights and new stat objects."""
    normalized = {}
    for cidr, value in raw_data.items():
        if isinstance(value, dict):
            normalized[cidr] = {
                "weight": clamp_subnet_weight(float(value.get("weight", MIN_SUBNET_WEIGHT))),
                "success_count": int(value.get("success_count", 0)),
                "fail_count": int(value.get("fail_count", 0)),
                "avg_speed": round(float(value.get("avg_speed", 0.0)), 3),
            }
        else:
            normalized[cidr] = {
                "weight": clamp_subnet_weight(float(value)),
                "success_count": 0,
                "fail_count": 0,
                "avg_speed": 0.0,
            }
    return normalized


def get_fail_penalty(stats):
    total = stats["success_count"] + stats["fail_count"]
    if total < HIGH_FAIL_RATE_MIN_SAMPLES:
        return BASE_FAIL_PENALTY

    fail_rate = stats["fail_count"] / total
    if fail_rate < HIGH_FAIL_RATE_THRESHOLD:
        return BASE_FAIL_PENALTY

    extra_penalty = min(0.25, (fail_rate - HIGH_FAIL_RATE_THRESHOLD) * 0.5)
    return BASE_FAIL_PENALTY - extra_penalty


def record_top_result(ip, ttlb, speed_kbps):
    top_results.append({
        "ip": ip,
        "ttlb": ttlb,
        "speed": speed_kbps,
    })
    top_results.sort(key=lambda item: (-item["speed"], item["ttlb"]))
    del top_results[TOP_RESULTS_LIMIT:]


def record_subnet_result(cidr, success, speed_kbps):
    stats = subnet_stats[cidr]
    if success:
        previous_count = stats["success_count"]
        next_count = previous_count + 1
        stats["success_count"] = next_count
        stats["avg_speed"] = round(
            ((stats["avg_speed"] * previous_count) + speed_kbps) / next_count,
            3,
        )
        stats["weight"] = clamp_subnet_weight(stats["weight"] + (speed_kbps / 100.0))
    else:
        stats["fail_count"] += 1
        stats["weight"] = clamp_subnet_weight(stats["weight"] * get_fail_penalty(stats))


def save_weights_to_disk():
    """Writes the final memory-buffered subnet stats back to subnets.json."""
    if not subnet_stats: return
    with lock:
        try:
            print(f"{SHOW_CURSOR}\n{YELLOW}[!] Saving updated subnet stats to {SUBNETS_FILE}...{RESET}")
            with open(SUBNETS_FILE, "w") as f:
                json.dump(subnet_stats, f, indent=2)
        except Exception as e:
            print(f"{RED}Error saving subnet stats: {e}{RESET}")


def write_scan_summary(interrupted=False):
    if not scan_summary_path:
        return

    with lock:
        finished_at = datetime.now()
        avg_latency = latency_total / success_count if success_count else 0.0
        avg_speed = speed_total / success_count if success_count else 0.0
        summary = {
            "started_at": scan_started_at.isoformat(timespec="seconds") if scan_started_at else None,
            "finished_at": finished_at.isoformat(timespec="seconds"),
            "interrupted": interrupted,
            "total_ips": total_ips,
            "checked_count": checked_count,
            "success_count": success_count,
            "blocked_count": block_count,
            "avg_latency_ms": round(avg_latency, 3),
            "avg_speed_kbps": round(avg_speed, 3),
            "best": top_results[0] if top_results else {
                "ip": None,
                "ttlb": 0.0,
                "speed": 0.0,
            },
            "top_results": top_results,
            "target": {
                "host": scanner_settings.get("host", DEFAULT_HOST),
                "sni": scanner_settings.get("sni", DEFAULT_HOST),
                "path": scanner_settings.get("path", DEFAULT_PATH),
                "alpn": scanner_settings.get("alpn", []),
                "insecure": scanner_settings.get("insecure", True),
            },
            "runtime": {
                "threads": runtime_settings["threads"],
                "timeout_min": runtime_settings["timeout_min"],
                "timeout_max": runtime_settings["timeout_max"],
                "recent": runtime_settings["recent"],
                "no_color": runtime_settings["no_color"],
            },
            "output_file": scan_output_path,
            "summary_file": scan_summary_path,
        }

    try:
        with open(scan_summary_path, "w") as f:
            json.dump(summary, f, indent=2)
    except Exception as e:
        print(f"{RED}Error saving scan summary: {e}{RESET}")


def signal_handler(sig, frame):
    global stop_requested
    stop_requested = True
    # Final save on interrupt
    save_weights_to_disk()
    write_scan_summary(interrupted=True)
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)


def get_adaptive_timeout():
    with lock:
        if not latencies: return runtime_settings["timeout_max"]
        sorted_lat = sorted(list(latencies))
        median = sorted_lat[len(sorted_lat) // 2]
        return max(
            runtime_settings["timeout_min"],
            min(runtime_settings["timeout_max"], (median / 1000) * 1.5),
        )


def format_bar(complete, total, width):
    if total <= 0:
        filled = 0
    else:
        filled = int((complete / total) * width)
    filled = max(0, min(width, filled))
    return "#" * filled + "-" * (width - filled)


def render_dashboard_locked(output_path):
    """Render an in-place terminal dashboard. Caller must hold lock."""
    percent = (checked_count / total_ips) * 100.0 if total_ips else 0.0
    terminal_width = shutil.get_terminal_size((100, 24)).columns
    bar_width = max(20, min(50, terminal_width - 34))
    bar = format_bar(checked_count, total_ips, bar_width)
    timeout = get_adaptive_timeout_unlocked()

    top_speeds = [item["speed"] for item in recent_results if item["success"]]
    latest_speed = top_speeds[-1] if top_speeds else 0.0
    latest_latency = next((item["ttlb"] for item in reversed(recent_results) if item["success"]), 0.0)

    lines = [
        f"{BOLD}{CYAN}argo-ip-radar{RESET}  {DIM}Ctrl+C saves subnet weights and exits{RESET}",
        f"Target    {scanner_settings.get('host', DEFAULT_HOST)}{scanner_settings.get('path', DEFAULT_PATH)} "
        f"SNI {scanner_settings.get('sni', DEFAULT_HOST)}",
        "",
        f"Progress  [{bar}] {checked_count}/{total_ips} ({percent:5.1f}%)",
        f"Working   {GREEN}{success_count}{RESET}   Blocked {RED}{block_count}{RESET}   Timeout {timeout:.2f}s",
        f"Latest    {latest_latency:6.1f}ms   {latest_speed:6.2f}kbps",
        f"{PINK}Top IPs{RESET}",
    ]

    for index in range(1, TOP_RESULTS_LIMIT + 1):
        if index <= len(top_results):
            item = top_results[index - 1]
            lines.append(
                f"{PINK}#{index:<2}      {item['ttlb']:6.1f}ms   {item['speed']:6.2f}kbps   "
                f"{item['ip']:<15}{RESET}"
            )
        else:
            lines.append(f"{PINK}#{index:<2}       0.0ms     0.00kbps   -{RESET}")

    lines.extend([
        "",
        f"{BOLD}Recent results{RESET}",
    ])

    if recent_results:
        for item in reversed(recent_results):
            color = GREEN if item["success"] else RED
            status = "WORKS" if item["success"] else "BLOCK"
            lines.append(
                f"{color}[{status}] {item['ip']:<15}{RESET} "
                f"{item['ttlb']:>7.1f}ms  {item['speed']:>7.2f}kbps  {item['reason']}"
            )
    else:
        lines.append(f"{DIM}Waiting for first result...{RESET}")
    
    lines.append(f"\nOutput {output_path}")
    sys.stdout.write(CURSOR_HOME + CLEAR_SCREEN + "\n".join(lines))
    sys.stdout.flush()


def get_adaptive_timeout_unlocked():
    if not latencies:
        return runtime_settings["timeout_max"]
    sorted_lat = sorted(list(latencies))
    median = sorted_lat[len(sorted_lat) // 2]
    return max(
        runtime_settings["timeout_min"],
        min(runtime_settings["timeout_max"], (median / 1000) * 1.5),
    )


def check_ip(ip: str, out_handle, prog_handle, output_path):
    global checked_count, success_count, block_count, latency_total, speed_total
    if stop_requested: return

    timeout = get_adaptive_timeout()
    start_time = time.time()
    success, speed_kbps, ttlb, reason = False, 0.0, 0.0, "conn-fail"

    try:
        with closing(socket.create_connection((ip, 443), timeout=timeout)) as sock:
            with shared_context.wrap_socket(sock, server_hostname=scanner_settings["sni"]) as tls:
                ws_key = base64.b64encode(os.urandom(16)).decode()
                req = make_ws_upgrade_request(scanner_settings, ws_key)
                tls.sendall(req.encode())

                resp_data = b""
                while b"\r\n\r\n" not in resp_data and len(resp_data) < 16384:
                    chunk = tls.recv(1024)
                    if not chunk: break
                    resp_data += chunk

                end_time = time.time()
                ttlb = (end_time - start_time) * 1000.0
                success, reason = validate_ws_upgrade(resp_data, ws_key)
                if resp_data:
                    content_size = len(resp_data) + len(req)
                    duration = max(0.001, end_time - start_time)

                    speed_kbps = (content_size * 8.0) / duration / 1024.0

                if success:
                    with lock:
                        latencies.append(ttlb)
    except socket.timeout:
        reason = "timeout"
    except ssl.SSLError:
        reason = "tls-failed"
    except OSError:
        reason = "conn-fail"

    with lock:
        checked_count += 1
        if success:
            success_count += 1
            latency_total += ttlb
            speed_total += speed_kbps
            record_top_result(ip, ttlb, speed_kbps)
        else:
            block_count += 1

        # Update subnet weights in memory
        ip_addr = ipaddress.ip_address(ip)
        for cidr, network in parsed_subnets:
            if ip_addr in network:
                record_subnet_result(cidr, success, speed_kbps)
                break

        recent_results.append({
            "ip": ip,
            "success": success,
            "ttlb": ttlb,
            "speed": speed_kbps,
            "reason": reason,
        })

        prog_handle.write(f"{ip}\n")
        prog_handle.flush()
        if success:
            # Saving: Storing as float in the text file for the sorter
            out_handle.write(f"{ip} | {ttlb:.1f}ms | {speed_kbps:.2f}kbps\n")
            out_handle.flush()
        render_dashboard_locked(output_path)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Scan Cloudflare IPs and keep only endpoints that complete a real TLS WebSocket upgrade."
    )
    parser.add_argument(
        "config",
        nargs="?",
        help="Optional vless:// URL. host, sni, path, alpn, and insecure are read from it.",
    )
    parser.add_argument("--host", help="Override HTTP Host / WebSocket host.")
    parser.add_argument("--sni", help="Override TLS SNI.")
    parser.add_argument("--path", help="Override WebSocket path, for example /config.")
    parser.add_argument("--alpn", help="Comma-separated TLS ALPN list, for example h2,http/1.1.")
    parser.add_argument("--threads", type=positive_int, default=MAX_THREADS)
    parser.add_argument("--timeout-min", type=positive_float, default=0.6)
    parser.add_argument("--timeout-max", type=positive_float, default=2.5)
    parser.add_argument("--recent", type=positive_int, default=RECENT_RESULTS_LIMIT)
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors and screen-control codes.")
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable certificate validation. Useful when scanning direct Cloudflare IPs.",
    )
    args = parser.parse_args()
    if args.timeout_min > args.timeout_max:
        parser.error("--timeout-min must be less than or equal to --timeout-max")
    return args


def main():
    global total_ips, checked_count, subnet_stats, parsed_subnets, scanner_settings, shared_context, recent_results
    global scan_started_at, scan_output_path, scan_summary_path

    args = parse_args()
    try:
        scanner_settings = build_settings(args)
    except ValueError as exc:
        print(f"{RED}Error: {exc}{RESET}")
        return
    runtime_settings.update({
        "threads": args.threads,
        "timeout_min": args.timeout_min,
        "timeout_max": args.timeout_max,
        "recent": args.recent,
        "no_color": args.no_color,
    })
    recent_results = deque(maxlen=args.recent)
    if args.no_color:
        disable_colors()
    shared_context = create_tls_context(scanner_settings)

    # Load subnets into memory at start
    try:
        with open(SUBNETS_FILE, "r") as f:
            subnet_stats = normalize_subnet_stats(json.load(f))
        parsed_subnets = [(cidr, ipaddress.ip_network(cidr)) for cidr in subnet_stats]
    except FileNotFoundError:
        print(f"{RED}Error: {SUBNETS_FILE} not found!{RESET}")
        return

    try:
        f_stats = os.stat(IPS_FILE)
        current_id = f"{f_stats.st_size}_{f_stats.st_mtime}"
        all_ips = [line.strip() for line in open(IPS_FILE) if line.strip()]
        total_ips = len(all_ips)
    except FileNotFoundError:
        return

    # (Previous Session Logic Here...)
    last_id = open(ID_FILE, "r").read().strip() if os.path.exists(ID_FILE) else ""
    if current_id != last_id:
        if os.path.exists(PROGRESS_FILE): os.remove(PROGRESS_FILE)
        with open(ID_FILE, "w") as f:
            f.write(current_id)
        checked_ips = set()
    else:
        checked_ips = set(line.strip() for line in open(PROGRESS_FILE) if line.strip()) if os.path.exists(
            PROGRESS_FILE) else set()

    remaining_ips = [ip for ip in all_ips if ip not in checked_ips]
    checked_count = total_ips - len(remaining_ips)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    scan_started_at = datetime.now()
    output_stem = scan_started_at.strftime('%Y-%m-%d_%H-%M')
    output_path = os.path.join(RESULTS_DIR, f"{output_stem}.txt")
    summary_path = os.path.join(RESULTS_DIR, f"{output_stem}_summary.json")
    scan_output_path = output_path
    scan_summary_path = summary_path
    print(HIDE_CURSOR + CLEAR_SCREEN, end="")
    with open(output_path, "a") as out_h, open(PROGRESS_FILE, "a") as prog_h:
        with lock:
            render_dashboard_locked(output_path)
        with ThreadPoolExecutor(max_workers=runtime_settings["threads"]) as executor:
            for ip in remaining_ips:
                if stop_requested: break
                executor.submit(check_ip, ip, out_h, prog_h, output_path)

    # Final save after completion
    save_weights_to_disk()
    write_scan_summary(interrupted=False)
    print(f"{SHOW_CURSOR}{GREEN}Done. Results written to {output_path}.{RESET}")


if __name__ == "__main__":
    main()
