#!/usr/bin/env bash
set -e

echo "[+] Cleaning old interfaces (if any)..."
for dev in tap0 tap1 br0; do
  ip link set $dev down 2>/dev/null || true
  ip link del $dev 2>/dev/null || true
done

echo "[+] Creating TAP devices..."
ip tuntap add dev tap0 mode tap
ip tuntap add dev tap1 mode tap

echo "[+] Creating single bridge (br0)..."
ip link add name br0 type bridge

echo "[+] Attaching TAP devices to bridge..."
ip link set tap0 master br0
ip link set tap1 master br0

echo "[+] Bringing interfaces up..."
ip link set tap0 up
ip link set tap1 up
ip link set br0 up

echo
echo "✅ Setup complete!"
echo "   tap0 ↔ br0 ↔ tap1"
echo
echo "Interface summary:"
bridge link show

echo "[+] Disabling bridge netfilter (for TAP forwarding)..."
sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null
sysctl -w net.bridge.bridge-nf-call-ip6tables=0 >/dev/null
sysctl -w net.bridge.bridge-nf-call-arptables=0 >/dev/null

bridge link set dev tap0 flood on
bridge link set dev tap1 flood on

sudo bridge fdb add 02:00:00:00:01:BB dev tap0 master static
sudo bridge fdb add 02:00:00:00:01:AA dev tap1 master static