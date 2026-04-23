
# Docker

```
chmod +x setup_nic.sh
docker compose up -d
```

livebookで `ex_tcp/livebook/L2_Ethernet/client.livemd`を開いて順序通りに実行します。

# WSL2

```
chmod +x setup_nic.sh
sudo bash setup_nic.sh
cd ex_tcp
```

ターミナルを２つ用意します。

```
iex -S mix
Ether.Host.start_link []
```

```
iex -S mix
Ether.Client.start_link []
Ether.Client.send_frame "HELLO\n"
```

# 実行確認

ホストに下記が出力されます

```
FROM LOCAL NIC
PSH_ACK
HELLO
```