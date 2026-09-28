# Testbed: two IPsec endpoints

FERA needs **two** IPsec endpoints that share a link and can reach each other's
*protected* network.  Three topologies are supported through the same topology
abstraction; the recommended one is the Linux network namespace testbed.

## Diagram

```
            Endpoint A (initiator)                  Endpoint B (responder)
        ┌──────────────────────────┐            ┌──────────────────────────┐
        │ protected: 10.20.0.1/24  │            │ protected: 10.30.0.1/24  │
        │ outer    : 10.10.10.1/24 │  veth pair │ outer    : 10.10.10.2/24 │
        │            fera-va  ◄────┼────────────┼────►  fera-vb            │
        └──────────────────────────┘            └──────────────────────────┘
              ▲                                           ▲
              │            IKEv2 negotiation              │
              │  UDP 500 / 4500     (captured here)       │
              │            ESP protected traffic          │
              └───────────────────────────────────────────┘
```

IPv6 variant: outer `fd00:10:10::1/64` ↔ `fd00:10:10::2/64`, protected
`fd00:20::1/64` ↔ `fd00:30::1/64` (ULA space, no global routing involved).

### Tunnel mode

| | value |
|---|---|
| outer header | `10.10.10.1 → 10.10.10.2` |
| inner (encapsulated) header | `10.20.0.1 → 10.30.0.1` |
| traffic selectors | `local_ts = 10.20.0.0/24`, `remote_ts = 10.30.0.0/24` |
| traffic target | `10.30.0.1` (endpoint B's protected address) |
| extra route on A | `ip route replace 10.30.0.0/24 via 10.10.10.2 src 10.20.0.1` |

### Transport mode

| | value |
|---|---|
| protected header | `10.10.10.1 → 10.10.10.2` (host to host only) |
| traffic selectors | `local_ts = 10.10.10.1/32`, `remote_ts = 10.10.10.2/32` |
| traffic target | `10.10.10.2` |
| extra route | none |

Transport mode with network selectors is rejected instead of being silently
generated (`tests/test_swanctl_config.py`).

## Recommended: Linux network namespaces (one host)

```bash
# create namespaces + addressing (generated from the topology file)
sudo python scripts/setup_netns_testbed.py --print-only     # review first

sudo python scripts/setup_netns_testbed.py --apply --start-charon
sudo python scripts/run_experiment.py --config configs/experiments/exp_000_*.yaml --update-manifest
sudo python scripts/setup_netns_testbed.py --stop-charon --teardown
```

What the script does (all generated, reviewable before execution):

1. deletes and recreates the namespaces `fera-a` / `fera-b` (idempotent),
2. creates one veth pair, MTU 1400 (headroom for the ESP overhead),
3. assigns outer + protected addresses (IPv4 and IPv6),
4. installs the routes that pin the protected source address,
5. optionally starts **one charon instance per namespace**, each with its own
   VICI socket (`/run/fera-testbed/charon-<a|b>.vici`), so `swanctl --uri`
   addresses exactly one endpoint.  Sockets live on a local Linux filesystem
   (under WSL the repository is a Windows mount, which does not support unix
   sockets reliably).

Verification steps for the environment:

```bash
ip netns exec fera-a ping -c 1 10.10.10.2      # outer reachability
ip netns exec fera-a ping -c 1 10.30.0.1       # protected reachability
/usr/lib/ipsec/charon --version                # charon present
swanctl --uri unix:///run/fera-testbed/charon-a.vici --stats
ip xfrm state                                   # needs CONFIG_XFRM_USER + root
```

## Alternative: two Linux VMs

Point the topology at remote endpoints — `command_prefix` is the only change:

```yaml
endpoints:
  a:
    name: endpoint-a
    role: initiator
    outer_ipv4: 192.0.2.10/32
    protected_ipv4: 10.20.0.1/24
    command_prefix: ["ssh", "fera@192.0.2.10"]
```

`run_experiment.py` then executes `swanctl`, `tcpdump`, `ping`, ... through
`ssh` on that host.  Requirements: key based SSH (no interactive password),
strongSwan installed, root (or `cap_net_admin,cap_net_raw` on the binaries).

## Alternative: containers

Only usable when the container has `CAP_NET_ADMIN`/`CAP_NET_RAW` and a kernel
with XFRM.  This is *not* the default path: the environment checker will report
XFRM availability, and FERA never assumes it.

## Platform support

| Platform | Status |
|---|---|
| Linux VM / bare metal | supported and recommended |
| Linux namespaces (same kernel) | supported (used by `setup_netns_testbed.py`) |
| WSL2 | works only if the WSL kernel exposes XFRM; `check_environment.py` probes `ip xfrm state` and reports the result (`docs/limitations.md` records what was actually proven in this environment) |
| Windows / macOS | capture and XFRM are unsupported — FERA refuses to run experiments and says why |

## Rules of the testbed

* the topology file is the single source of truth for addresses, selectors and
  the traffic target: generated strongSwan configuration, netns scripts and
  ground truth all derive from it;
* no root-only mutation happens without an explicit `--apply`/run command;
* the PSK is generated per run, stored mode 0600 under `data/raw/<exp>/secrets/`
  (git-ignored), never logged and never written into the reproducible
  `swanctl.conf`.
