# Two real VMs over SSH (VirtualBox)
#
# Use this when the endpoints are separate machines rather than network
# namespaces on one host.  Each VM runs the ordinary system strongSwan with its
# own already-working IKEv2 + CHILD_SA, and FERA drives it over SSH.
#
#     python scripts/preflight_ssh.py --topology configs/templates/testbed_topology_ssh.yaml
#     python scripts/run_experiment.py --topology configs/templates/testbed_topology_ssh.yaml \
#         --config <one-baseline>.yaml --dry-run
#     python scripts/run_experiment.py --topology configs/templates/testbed_topology_ssh.yaml \
#         --config <one-baseline>.yaml --overwrite --update-manifest
#
# The netns topology remains the shipped default and is untouched by this one.

## What `kind: ssh` means

`kind` is explicit on every endpoint and is **not** inferred from the shape of
`command_prefix`:

| kind | endpoint is | VICI socket FERA uses |
|---|---|---|
| `local` | this machine | the host's default socket |
| `netns` | a namespace on this machine | a FERA-private socket it started |
| `ssh` | **another machine** | **that machine's own default socket** |

The ssh row is the important one. FERA must *not* pass `--uri` for a remote
endpoint: the private path it would generate lives on the controller, not on the
VM, so pointing at it addresses a file that does not exist there. `swanctl` on
the VM therefore uses its normal local socket - which is why the VMs must
already have working strongSwan, and why you should not reconfigure them.

## Fields you must set

```yaml
endpoints:
  a:
    kind: ssh            # required, or the endpoint is treated as local
    ssh_host: <host>     # required with kind: ssh
    ssh_user: <user>     # optional
    ssh_port: <port>     # optional
    ssh_identity: <path> # optional
    capture_interface: enp0s8
    outer_ipv4: 10.10.10.1/24
    # protected_ipv4: 10.20.0.1/24   # only for tunnel mode
```

`kind: ssh` without `ssh_host` is rejected, and `ssh_host` without `kind: ssh` is
rejected too - a remote address on a local endpoint would silently do the wrong
thing.

### Do not assume 127.0.0.1:2221 works from WSL

A VirtualBox forwarded port that answers **from Windows** is no evidence that it
answers **from WSL**. Verify first, then put whatever works in `ssh_host`:

```bash
ssh -o BatchMode=yes -p 2221 <user>@127.0.0.1 true    # run this FROM WSL
```

If that fails, try the VirtualBox host-only address (`ip addr` on Windows shows
e.g. `192.168.56.1`), or enable WSL's mirrored/localhost forwarding. Do not
work around it by disabling the preflight.

## Running it

1. **Preflight** - fails clearly if either VM is unreachable:

   ```bash
   python scripts/preflight_ssh.py --topology configs/templates/testbed_topology_ssh.yaml
   ```

   Checks, per endpoint: non-interactive SSH, `swanctl`/`ip`/`tcpdump` present,
   `swanctl --version`, `swanctl --list-sas` answering on the VM's own socket,
   `enp0s8` present, the expected address configured, tcpdump usable, peer
   ping. An unanswered ping is reported *inconclusive*, not a failure - IKE uses
   UDP 500/4500 and many hosts filter ICMP.

   Preflight passing means the machines are **reachable and capable**. It is not
   evidence of any experiment, and the script will never print otherwise.

2. **Dry run** - generates the plan, touches nothing, marks the sample invalid:

   ```bash
   python scripts/run_experiment.py --topology configs/templates/testbed_topology_ssh.yaml \
       --config <one-baseline>.yaml --dry-run
   ```

3. **ONE real baseline experiment** - not the matrix:

   ```bash
   python scripts/run_experiment.py --topology configs/templates/testbed_topology_ssh.yaml \
       --config <one-baseline>.yaml --overwrite --update-manifest
   ```

4. **Validate its capture before anything else.** A run that produced no real
   pcap is never marked reusable, whatever the rest of the run says:

   ```bash
   python scripts/verify_dataset.py --help
   tshark -r data/raw/<exp>/capture.pcap -Y esp | head
   ```

5. **Only then** consider batch/matrix collection.

## Tunnel mode needs protected addresses

The VMs expose only `enp0s8`, which gives host-to-host (transport) selectors
for free. Tunnel mode protects a subnet *behind* each endpoint, so it needs
`protected_ipv4` on both, and those addresses must genuinely exist on the VMs.
Without them FERA refuses tunnel mode with a clear message rather than
generating selectors for addresses that do not exist.

## What was deliberately not changed

The VMs' strongSwan configuration, the experiment matrix, capture validation,
manifests, dataset builder and ML pipeline are all untouched. This is a routing
and preflight change only: everything FERA does beyond reaching the endpoint is
the code that already runs for the netns testbed.
