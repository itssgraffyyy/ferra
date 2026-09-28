# Platform Limitations & Execution Boundaries

This document details platform limitations, prerequisites, and degradation behaviours
within FERA Stage 1.

---

## Operating System Support

### Linux (Bare Metal or Virtual Machine)
* **Status**: Fully Supported (Target Deployment Platform).
* **Requirements**:
  * Root privileges (`sudo`) or `CAP_NET_ADMIN` + `CAP_NET_RAW`.
  * Linux kernel with XFRM support enabled (`CONFIG_XFRM`, `CONFIG_INET_ESP`).
  * `strongswan` and `strongswan-swanctl` packages installed.
  * `tcpdump` or `dumpcap` for network packet capture.

### Windows Subsystem for Linux (WSL2)
* **Status**: Conditional / Partial.
* **Limitations**:
  * Default WSL2 kernels may lack full XFRM transformations or state tracking in network namespaces.
  * Unix domain sockets across `/mnt/c` mounts are not supported by the Linux kernel; VICI runtime sockets must reside on native Linux mounts (e.g. `/run` or `/tmp`).
  * Run `scripts/check_environment.py` inside WSL to probe kernel XFRM capabilities before executing real experiments.

### Windows / macOS Native
* **Status**: Development, Dry-Run, and Validation Only.
* **Limitations**:
  * Kernel IPsec (XFRM) and Linux network namespaces (`ip netns`) are unavailable.
  * Packet capture via `tcpdump` inside namespaces is unsupported.
  * The full test suite, schema validation, configuration generator, dry-run runner, and offline PCAP parser execute natively on Windows and macOS.

---

## Tool Availability & Fallback Behaviour

| Tool | If Present | If Missing / Fallback |
|------|------------|-----------------------|
| `strongSwan` | Live tunnel negotiation | Fails with `IPSEC_DAEMON_NOT_FOUND` in live runs; fully mockable in dry-run/unit tests |
| `tcpdump` / `dumpcap` | Full raw packet capture | Fails with `CAPTURE_TOOL_NOT_AVAILABLE` in live runs; dry-run bypasses capture |
| `tshark` | Protocol hierarchy sanity checking | Falls back to internal pure-Python `pcap_scan.py` frame parser |
| `curl` / `ping` / `iperf3` | External traffic generation | Falls back to in-process native socket traffic generators (`fera.traffic.native`) |
