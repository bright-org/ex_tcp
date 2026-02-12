defmodule ExTCP do
  @ipproto_tcp 6

  @moduledoc """
  127.0.0.1:PORT に対して、Raw IP で SYN を送り、SYN-ACK が返るかだけ確認する極小プローブ。
  - IPv4 固定ヘッダ(20B)
  - TCP は SYN(+MSS) 生成のみ
  - 受信側は IP/TCP を最低限だけパースして SYN-ACK を検出
  - RST/ACK などの応答は送らない（確認のみ）
  必要権限: root もしくは CAP_NET_RAW
  """

  import Bitwise

  @ip {127, 0, 0, 1}
  @src_port 40000
  @dst_port 40001

  # 制御フラグ
  @fin 0x01
  @syn 0x02
  @psh 0x08
  @rst 0x04
  @ack 0x10
  @syn_ack 0x12
  @psh_ack 0x18
  @fin_ack 0x11
  @fin_psh_ack 0x19
  @urg 0x20

  @doc """
  Socket の受信ループ。`connect_stream/3` で得たソケットを `%ExTCP.TcpState{}` に渡して呼び出す。

  受信メッセージ: `{:tcp, sock, data}` / `{:tcp_closed, sock}`（gen_tcp アクティブモード）

  ## Example

      {:ok, sock} = ExTCP.connect_stream("127.0.0.1", 40001)
      ExTCP.loop(%ExTCP.TcpState{socket: sock, phase: :status, parse_fn: &parse/1})
  """
  def loop(%ExTCP.TcpState{} = state) do
    receive do
      {:tcp, _sock, data} ->
        state = on_data(data, state)
        if state.phase == :done do
          :gen_tcp.close(state.socket)
          {:ok, state.body}
        else
          loop(state)
        end

      {:tcp_closed, _sock} ->
        {:ok, state.body}
    end
  end

  def on_data(data, %{parse_fn: parse_fn} = state) do
    state
    |> append_buffer(data)
    |> parse_fn.()
  end

  def append_buffer(state, data) do
    %{state | buffer: state.buffer <> IO.iodata_to_binary(data)}
  end

  @doc """
  Raw ソケットで 3 way handshake のみ行い、送信に必要な情報を返す。
  `send_psh_ack` でリクエスト送信後、`wait_segment(sock, 0x10, flow, deadline)` → `receive_all_response_packets` → `close_connection` で受信・クローズする。
  """
  def connect_raw(dst_ip, dst_port, opts \\ []) do
    src_ip = Keyword.get(opts, :src_ip, @ip)
    src_port = Keyword.get(opts, :src_port, @src_port)
    timeout_ms = Keyword.get(opts, :timeout_ms, 100_000)

    {:ok, sock} = :socket.open(:inet, :raw, :tcp)
    :ok = :socket.setopt(sock, :ip, :hdrincl, true)

    iss = :rand.uniform(0x7FFFFFFF)
    send_syn(sock, src_ip, src_port, dst_ip, dst_port, iss)

    deadline = System.monotonic_time(:millisecond) + timeout_ms
    flow = {src_ip, src_port, dst_ip, dst_port}

    case wait_segment(sock, @syn_ack, flow, deadline) do
      {:ok, pkt} ->
        seq = iss + 1
        ack = pkt.seq + 1
        send_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, ack)
        {:ok, sock, seq, ack, flow}

      {:error, reason} ->
        :socket.close(sock)
        {:error, reason}
    end
  end

  @doc """
  任意の IPv4 宛に 3 way handshakeしてデータ送信する（Raw ソケット。loop には connect_stream を使う）
  handshake は connect_raw に委譲する。
  """
  def connect(
        dst_ip \\ @ip,
        dst_port \\ @dst_port,
        src_ip \\ @ip,
        src_port \\ @src_port,
        timeout_ms \\ 100_000
      ) do
    opts = [src_ip: src_ip, src_port: src_port, timeout_ms: timeout_ms]

    case connect_raw(dst_ip, dst_port, opts) do
      {:ok, sock, seq, ack, flow} ->
        {src_ip, _src_port, dst_ip, _dst_port} = flow

        IO.puts("HTTP request")
        req = "GET / HTTP/1.0\r\n\r\n"
        send_psh_ack(sock, src_ip, elem(flow, 1), dst_ip, elem(flow, 3), seq, ack, req)

        seq = seq + byte_size(req)
        deadline = System.monotonic_time(:millisecond) + timeout_ms

        case wait_segment(sock, @ack, flow, deadline) do
          {:ok, ack_pkt} ->
            IO.puts("Receiving HTTP response")
            {final_ack, _body} = receive_all_response_packets(sock, flow, deadline, seq, ack_pkt.seq)

            send_ack(sock, src_ip, elem(flow, 1), dst_ip, elem(flow, 3), seq, final_ack)

            close_connection(sock, src_ip, elem(flow, 1), dst_ip, elem(flow, 3), seq, final_ack, flow)

          {:error, reason} ->
            IO.puts("ACK wait error: #{inspect(reason)}")
            :socket.close(sock)
            {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc """
  PSH+ACK / FIN+PSH+ACK をすべて受信し、ペイロードを連結する。
  戻り値: `{final_ack, body_binary}`。
  """
  def receive_all_response_packets(sock, {src_ip, src_port, dst_ip, dst_port} = flow, deadline_ms, my_seq, server_seq, acc \\ <<>>) do
    short_deadline = System.monotonic_time(:millisecond) + 1000

    case wait_segment(sock, @psh_ack, flow, short_deadline) do
      {:ok, pkt} ->
        new_server_seq = pkt.seq + byte_size(pkt.payload)
        send_ack(sock, src_ip, src_port, dst_ip, dst_port, my_seq, new_server_seq)
        receive_all_response_packets(sock, flow, deadline_ms, my_seq, new_server_seq, acc <> pkt.payload)

      {:error, _} ->
        case wait_segment(sock, @fin_psh_ack, flow, short_deadline) do
          {:ok, pkt} ->
            new_server_seq = pkt.seq + byte_size(pkt.payload)
            send_ack(sock, src_ip, src_port, dst_ip, dst_port, my_seq, new_server_seq)
            {new_server_seq, acc <> pkt.payload}

          {:error, _} ->
            {server_seq, acc}
        end
    end
  end

  @doc """
  FIN+ACK を送り、サーバーの ACK/FIN を受信して接続を閉じる。
  サーバーは ACK と FIN(+PSH+ACK) の到着順が入れ替わることがあるため、
  まず「ACK または FIN 系」のいずれか1つを受け取り、それに応じて処理する。
  """
  def close_connection(sock, src_ip, src_port, dst_ip, dst_port, seq, ack, flow) do
    IO.puts("Send FIN+ACK")
    send_fin_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, ack)
    seq = seq + 1

    IO.puts("Waiting for server ACK or FIN (confirm FIN+ACK)")
    short_fin_deadline = System.monotonic_time(:millisecond) + 2000

    # ACK(0x10) / FIN+PSH+ACK(0x19) / FIN+ACK(0x11) / FIN(0x01) のいずれか1つを受け取る（到着順でブロックしない）
    case wait_segment_one_of(sock, [@ack, @fin_psh_ack, @fin_ack, @fin], flow, short_fin_deadline) do
      {:ok, pkt, @ack} ->
        # 先に ACK が来た → 続けて FIN 系を待つ
        case wait_segment_one_of(sock, [@fin_psh_ack, @fin_ack, @fin], flow, short_fin_deadline) do
          {:ok, finpkt, flags} ->
            ack_num = if (flags &&& @psh) != 0, do: finpkt.seq + byte_size(finpkt.payload), else: finpkt.seq + 1
            send_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, ack_num)
            :socket.close(sock)
            :ok
          {:error, reason} ->
            IO.puts("FIN wait error: #{inspect(reason)} - closing socket")
            :socket.close(sock)
            :ok
        end

      {:ok, finpkt, flags} when (flags &&& @fin) != 0 ->
        # 先に FIN 系が来た → ACK を返して終了（ACK 待ちは省略可能）
        ack_num = if (flags &&& @psh) != 0, do: finpkt.seq + byte_size(finpkt.payload), else: finpkt.seq + 1
        send_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, ack_num)
        :socket.close(sock)
        :ok

      {:error, reason} ->
        IO.puts("ACK/FIN wait error: #{inspect(reason)} - closing socket")
        :socket.close(sock)
        :ok
    end
  end

  # 指定したフラグのいずれかに一致するセグメントが来るまで待つ。戻り値: {:ok, pkt, matched_flags} | {:error, reason}
  defp wait_segment_one_of(sock, acceptable_flags, {src_ip, sp, dst_ip, dp} = flow, deadline_ms) do
    now = System.monotonic_time(:millisecond)
    if now >= deadline_ms do
      {:error, :timeout}
    else
      :socket.recv(sock)
      |> case do
        {:ok, bin} ->
          bin
          |> Ether.Ipv4.parse()
          |> case do
            {:ok, {^dst_ip, ^src_ip, _proto, tcp_bin}} ->
              tcp_bin
              |> parse_tcp()
              |> case do
                %{sp: spv, dp: dpv, flags: fl, payload: _payload} = pkt ->
                  if spv == dp and dpv == sp and (fl &&& @rst) == @rst do
                    IO.puts("TCP #{spv}->#{dpv} flags=0x#{Integer.to_string(fl, 16)} - RST received: connection reset")
                    {:error, :connection_reset}
                  else
                    if spv == dp and dpv == sp and fl in acceptable_flags do
                      IO.puts("TCP #{spv}->#{dpv} flags=0x#{Integer.to_string(fl, 16)}")
                      {:ok, pkt, fl}
                    else
                      wait_segment_one_of(sock, acceptable_flags, flow, deadline_ms)
                    end
                  end
                %{sp: ^dp, dp: ^sp} ->
                  wait_segment_one_of(sock, acceptable_flags, flow, deadline_ms)
                _ ->
                  wait_segment_one_of(sock, acceptable_flags, flow, deadline_ms)
              end
            {:ok, _} ->
              wait_segment_one_of(sock, acceptable_flags, flow, deadline_ms)
            :error ->
              {:error, :parse_error}
          end
        {:select, _} ->
          {:error, :timeout}
        other ->
          {:error, other}
      end
    end
  end

  defp receive_response_loop(sock, {src_ip, src_port, dst_ip, dst_port} = flow, deadline_ms, acc_data, my_seq, expected_seq, _original_deadline) do
    now = System.monotonic_time(:millisecond)

    if now >= deadline_ms do
      {:ok, acc_data}
    else
      case wait_segment(sock, @psh_ack, flow, deadline_ms) do
        {:ok, pkt} ->
          payload = pkt.payload
          new_data = acc_data <> payload
          new_seq = my_seq
          new_expected_seq = pkt.seq + byte_size(payload)

          IO.puts("Received payload (hex dump):")
          IO.puts(Base.encode16(payload, case: :lower))
          IO.puts("")

          send_ack(sock, src_ip, src_port, dst_ip, dst_port, new_seq, new_expected_seq)

          receive_response_loop(sock, flow, deadline_ms, new_data, new_seq, new_expected_seq, deadline_ms)

        {:error, :connection_reset} ->
          IO.puts("Error: connection reset")
          {:error, :connection_reset}

        {:error, reason} ->
          case wait_segment(sock, @ack, flow, deadline_ms) do
            {:error, :connection_reset} ->
              IO.puts("Error: connection reset")
              {:error, :connection_reset}
            {:ok, ack_pkt} ->
              short_deadline = System.monotonic_time(:millisecond) + 1000
              case wait_segment(sock, @psh_ack, flow, short_deadline) do
                {:ok, pkt} ->
                  payload = pkt.payload
                  new_data = acc_data <> payload
                  new_expected_seq = pkt.seq + byte_size(payload)
                  IO.puts("Received payload (hex dump):")
                  IO.puts(Base.encode16(payload, case: :lower))
                  IO.puts("")
                  send_ack(sock, src_ip, src_port, dst_ip, dst_port, my_seq, new_expected_seq)
                  receive_response_loop(sock, flow, deadline_ms, new_data, my_seq, new_expected_seq, deadline_ms)
                {:error, _} ->
                  if byte_size(acc_data) > 0 do
                    IO.puts("Received full data (hex dump):")
                    IO.puts(Base.encode16(acc_data, case: :lower))
                  end
                  {:ok, acc_data}
              end

            {:error, _} ->
              if byte_size(acc_data) > 0 do
                IO.puts("Received full data (hex dump):")
                IO.puts(Base.encode16(acc_data, case: :lower))
              end
              {:ok, acc_data}
          end
      end
    end
  end


  @doc """
  送信用ヘルパ。:socket.open(:inet, :raw, 6) ＋ IP_HDRINCL=true 済みのtxに送る。
  """
  def send_syn(tx, src_ip, src_port, dst_ip, dst_port, iss, window \\ 65_535) do
    send_tcp(tx, src_ip, src_port, dst_ip, dst_port, iss, 0, 0x02, window)
  end

  def send_ack(tx, src_ip, src_port, dst_ip, dst_port, seq, ack, window \\ 65_535) do
    send_tcp(tx, src_ip, src_port, dst_ip, dst_port, seq, ack, 0x10, window)
  end

  def send_psh_ack(tx, src_ip, src_port, dst_ip, dst_port, seq, ack, payload, window \\ 65_535) do
    send_tcp(tx, src_ip, src_port, dst_ip, dst_port, seq, ack, 0x18, window, payload)
  end

  def send_fin_ack(tx, src_ip, src_port, dst_ip, dst_port, seq, ack, window \\ 65_535) do
    send_tcp(tx, src_ip, src_port, dst_ip, dst_port, seq, ack, @fin_ack, window)
  end

  @doc """
  指定フラグの TCP セグメントが届くまで待つ。戻り値: `{:ok, pkt}` / `{:error, reason}`。
  Req から ACK 待ちで `ExTCP.wait_segment(sock, 0x10, flow, deadline)` を呼ぶ（0x10 = ACK）。
  """
  def wait_segment(sock, flags, {src_ip, sp, dst_ip, dp} = flow, deadline_ms) do
    now = System.monotonic_time(:millisecond)

    if now >= deadline_ms do
      {:error, :timeout}
    else
      # 1回のrecvに残り時間をそのまま渡す（select発生でもスピンしにくくする）

      :socket.recv(sock)
      |> case do
        {:ok, bin} ->
          bin
          |> Ether.Ipv4.parse()
          |> case do
            {:ok, {^dst_ip, ^src_ip, _proto, tcp_bin}} ->
              tcp_bin
              |> parse_tcp()
              |> case do
                %{sp: spv, dp: dpv, flags: fl, seq: rseq, payload: payload} = pkt ->
                  # RSTフラグが来た場合は接続がリセットされた
                  if spv == dp and dpv == sp and (fl &&& @rst) == @rst do
                    IO.puts("TCP #{spv}->#{dpv} flags=0x#{Integer.to_string(fl, 16)} - RST received: connection reset")
                    {:error, :connection_reset}
                  else
                    if spv == dp and dpv == sp and fl == flags do
                      IO.puts("TCP #{spv}->#{dpv} flags=0x#{Integer.to_string(fl, 16)}")
                      {:ok, pkt}
                    else
                      wait_segment(sock, flags, flow, deadline_ms)
                    end
                  end

                # デバッグ/混線時の観測: アドレス/ポートは合うがSYN+ACKではない（例：反射SYN）
                %{sp: ^dp, dp: ^sp} ->
                  wait_segment(sock, flags, flow, deadline_ms)

                _ ->
                  wait_segment(sock, flags, flow, deadline_ms)
              end

            {:ok, _} ->
              wait_segment(sock, flags, flow, deadline_ms)

            :error ->
              {:error, "Unexpected error"}
          end

        {:select, _} ->
          {:error, :timeout}

        other ->
          {:error, other}
      end
    end
  end

  defp send_tcp(
         tx,
         src_ip,
         src_port,
         dst_ip,
         dst_port,
         seq,
         ack,
         flags,
         window \\ 65_535,
         payload \\ <<>>
       ) do
    tcp0 = tcp_header(src_port, dst_port, seq, ack, flags, window)

    tcp = tcp_checksum(src_ip, dst_ip, tcp0 <> payload)

    ip = ipv4(src_ip, dst_ip, 20 + byte_size(tcp) + byte_size(payload))

    pkt = ip <> tcp <> payload
    :socket.sendto(tx, pkt, %{family: :inet, addr: dst_ip, port: dst_port})
  end

  defp tcp_checksum({a, b, c, d} = src_ip, {e, f, g, h} = dst_ip, tcp_seg) do
    pseudo = <<a, b, c, d, e, f, g, h, 0, @ipproto_tcp, byte_size(tcp_seg)::16>>
    csum = csum16(pseudo <> tcp_seg)
    :binary.part(tcp_seg, 0, 16) <> <<csum::16>> <> <<0::16>>
  end

  # 16bit one's complement checksum
  defp csum16(bin) when is_binary(bin) do
    # 16bit単位で加算（奇数長なら最後の1バイトを上位に詰めて加算）
    sum =
      for <<w::16 <- bin>>, reduce: 0 do
        acc -> acc + w
      end
      |> then(fn s ->
        if rem(byte_size(bin), 2) == 1 do
          s + (:binary.last(bin) <<< 8)
        else
          s
        end
      end)

    # キャリー折り返し
    sum = (sum &&& 0xFFFF) + (sum >>> 16)
    sum = (sum &&& 0xFFFF) + (sum >>> 16)
    bnot(sum) &&& 0xFFFF
  end

  ## ===== IPv4: 20B 固定ヘッダ（IP_HDRINCL 前提）=====
  def ipv4({a, b, c, d}, {e, f, g, h}, tot) do
    ver_ihl = (4 <<< 4) + 5
    tos = 0
    ttl = 64
    id = 0x2D_D5

    # DF
    flags_frag = 1 <<< 14
    # proto=6(TCP)
    base =
      <<ver_ihl, tos, tot::16, id::16, flags_frag::16, ttl, 6, 0::16, a, b, c, d, e, f, g, h>>

    sum = csum16(base)
    <<ver_ihl, tos, tot::16, id::16, flags_frag::16, ttl, 6, sum::16, a, b, c, d, e, f, g, h>>
  end

  def tcp_header(src_port, dst_port, seq, ack, flags, window \\ 65_535) do
    doff = 5

    <<
      src_port::16, dst_port::16,
      seq::32,
      ack::32,
      (doff <<< 12) + flags::16, window::16,
      0::16, 0::16
    >>
  end

  defp parse_tcp(
         <<sp::16, dp::16, seq::32, ack::32, doff_flags, flags, _wnd::16, _::16, _::16,
           rest::binary>>
       ) do
    %{
      sp: sp,
      dp: dp,
      seq: seq,
      ack: ack,
      hlen: (doff_flags >>> 4) * 4,
      flags: flags,
      payload: rest
    }
  end
end
