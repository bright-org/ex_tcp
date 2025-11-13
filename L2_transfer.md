chmod +x setup_nic.sh
sudo bash setup_nic.sh
cd ex_tcp

ターミナルを２つ用意します

```
iex -S mix
Ether.Host.start_link []
```

```
iex -S mix
Ether.Client.start_link []
Ether.Client.send_frame "HELLO\n"
```

ホストに下記が出力されます

```
FROM LOCAL NIC
PSH_ACK
HELLO
```


Linux bridge はデフォルトで
net.bridge.bridge-nf-call-iptables=1
などの設定が有効になっており、bridge 経由の IPv4 フレームを iptables の filter テーブル に通します。
→ IPv6 ND などは通るが IPv4 が iptables で DROP される、というパターンでした。