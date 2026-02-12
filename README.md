# argo-ip-radar

python builtin, a high-precision, adaptive network diagnostic suite designed for low-bandwidth (500–600 kbps) and filtered environments. **argo-ip-radar** utilizes weighted subnet analysis and real-time performance feedback to identify the most stable Cloudflare entry points, specifically measuring **WebSocket (WS)** connection speeds for Argo Tunnel configurations.

---

## Table of Contents

- [**Description**](#description)
- [**Features**](#features)
- [**Requirements**](#requirements)
- [**Usage**](#usage)
- [**Algorithm**](#how-it-works)
- [**License**](#license)

---

## Description

In regions with aggressive internet filtering and unstable connections, standard network scanners often fail due to fixed timeouts and high protocol overhead. **argo-ip-radar** is engineered specifically for these constraints. It treats each network subnet as a dynamic entity, “learning” which ranges provide the best **WebSocket (WS)** throughput and lowest latency through a floating-point weighting system.

By mimicking standard browser headers and using adaptive, median-based timeouts, the tool finds “clean” IPs that remain hidden from Deep Packet Inspection (DPI) while maximizing the utility of a limited 600 kbps link.

---

## Features

* **WebSocket Speed Verification**
  Specifically tests the throughput of WS-compatible paths to ensure stability for 3x-ui and Argo tunnels.

* **Adaptive Median Timeout**
  Automatically adjusts connection limits based on current network jitter to prevent false block reports on unstable links.

* **Weighted Subnet Discovery**
  Uses a specialized algorithm to prioritize scanning in high-performing CIDR blocks based on historical success stored in `subnets.json`.

* **High-Precision Throughput**
  Measures speed as a floating-point value (kbps) to distinguish between marginal and stable connections without rounding errors.

* **Memory-Buffered Logging**
  Updates subnet performance scores in RAM and writes to disk only upon completion or interruption to protect network I/O performance.

---

## Requirements

* **Python 3.8+**
* **`subnets.json`**
  Tracking file for Cloudflare CIDR blocks and their current performance weights.
* **Network**
  An active connection (optimized for 500–600 kbps bottlenecks).

---

## Usage

### 1. Generate Weighted IPs

Run the generator to create an `ips.txt` file based on the current intelligence in `subnets.json`. Subnets with better historical performance are favored.

```bash
python ip-gen.py
```

---

### 2. Run the Radar

Execute the scanner to test **WebSocket connection** connectivity and true throughput.

```bash
python web-check.py
```

> **Note:** Press `Ctrl+C` at any time to stop. The script will automatically save updated subnet weights to disk before exiting.

---

### 3. Sort Results

Filter the working IPs to identify the best candidates for your configuration.

```bash
python sorter.py
```

---

## How it Works

The project utilizes an **Exponentially Weighted Moving Average (EWMA)** for its radar logic.

1. **Exploration**
   IPs are selected from multiple subnets based on their current weights.

2. **Evaluation**
   Each IP undergoes:

   * TCP connection
   * TLS handshake
   * Raw data transfer of `/cdn-cgi/trace` to simulate and measure **WebSocket connection** speed

3. **Reinforcement**

   * **PASS:** Subnet weight increases by `(speed_kbps / 100.0)`
   * **BLOCK:** Subnet weight is penalized by 10% (`weight × 0.9`)

4. **Adaptation**
   Future scans naturally prioritize high-performing subnets while avoiding filtered or throttled ranges.

---

## License

This project is licensed under the **MIT License**.
