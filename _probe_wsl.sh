echo "=== uname ==="; uname -a
echo "=== os ==="; ( . /etc/os-release; echo "$PRETTY_NAME" ) 2>/dev/null
echo "=== init ==="; ps -p 1 -o comm= 2>/dev/null
echo "=== tools ==="
for t in swanctl ipsec charon charon-systemd strongswan tcpdump tshark dumpcap iperf3 curl python3 apt-get ip ping6 ss; do
  printf '%s: %s\n' "$t" "$(command -v "$t" 2>/dev/null || echo MISSING)"
done
echo "=== xfrm plumbing ==="
echo "proc_net_xfrm_stat: $(test -f /proc/net/xfrm_stat && echo present || echo absent)"
echo "proc_config_gz: $(test -f /proc/config.gz && echo present || echo absent)"
echo "modules_dir: $(ls /lib/modules 2>/dev/null | tr '\n' ' ')"
lsmod 2>/dev/null | grep -iE 'xfrm|esp|ah4|af_key' || echo no_ipsec_modules_loaded
echo "--- ip xfrm state ---"
ip xfrm state 2>&1 | head -3
echo "--- kernel config ---"
if test -f /proc/config.gz; then zcat /proc/config.gz | grep -E 'CONFIG_(XFRM|INET_ESP|INET_AH|INET6_ESP|NET_KEY|USER_NS|NET_NS)'; fi
echo "=== namespaces ==="
ip netns add fera_probe_ns 2>&1 && echo "netns: OK" && ip netns del fera_probe_ns || echo "netns: FAILED"
ip link add fera_v0 type veth peer name fera_v1 2>&1 && echo "veth: OK" && ip link del fera_v0 || echo "veth: FAILED"
echo "=== caps ==="; id; grep -E 'Cap(Eff|Bnd)' /proc/self/status
echo "=== ipv6 ==="; cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null
echo "=== network ==="
timeout 20 curl -sS -o /dev/null -w 'pypi_http=%{http_code}\n' https://pypi.org/simple/ 2>&1 || echo curl_to_pypi_failed
echo "=== DONE ==="
