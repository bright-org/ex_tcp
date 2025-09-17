# 概要

Elixirによる:gen_tcpや:inetに依存しないTCP/IPスタック実装
Erlangの資産は:socketを利用します。

# Getting Stated

## Docker & Livebook

本ディレクリにあるdocker-compose.ymlを利用してください。

```
$ chmod +x fw-entrypoint.sh
$ docker compose up -d --build
```

ex_tcp/livebook/client.livemdを開いて実行します。

## 共通

OSが勝手にRSTで処理しないようにフィルターを設定します。

```
sudo iptables -I OUTPUT 1 -o lo -p tcp --tcp-flags RST RST \
  -s 127.0.0.1 --sport 40000 \
  -d 127.0.0.1 --dport 40001 -j DROP
```

## WSL

beam.smpにcap_net_rawを権限を付与する必要があります。

```
$ ERL_ROOT=$(erl -noshell -eval 'io:format("~s",[code:root_dir()]), halt().')
$ ls -d "$ERL_ROOT"/erts-*/bin/beam.smp
$ sudo setcap cap_net_raw+ep $(which beam.smp)
```

# Getting Start

TCPクライアントのみを実装しているため、ホストを用意します。

## TCPホストを用意

```bash
nc -lv 127.0.0.1 40001
```

Elixirで完結させたい場合は下記で行います。
ホストは未実装なので:gen_tcpを利用しています。

```bash
elixir recv.exs
```


## TCPクライアント

```bash
iex -S mix
iex> ExTCP.connect
```

## Expect

```
$ nc -lv 127.0.0.1 40001
Listening on localhost 40001
Connection received on localhost 40000
hello
```

```
iex(1)> ExTCP.probe_ip
TCP 40000->40001 flags=0x2
TCP 40001->40000 flags=0x12
:ok
```