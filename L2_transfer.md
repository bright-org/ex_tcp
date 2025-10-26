sudo bash setup_nic.sh

iex -S mix
Ether.Port.start_link []
Ether.Tx.handshake

$ sudo tcpdump -i tap1 -nn -vvv ip and tcp

Linux bridge はデフォルトで
net.bridge.bridge-nf-call-iptables=1
などの設定が有効になっており、bridge 経由の IPv4 フレームを iptables の filter テーブル に通します。
→ IPv6 ND などは通るが IPv4 が iptables で DROP される、というパターンでした。