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
  ストリームソケットで TCP 接続し、`ExTCP.loop/1` で使えるソケットを返す。

  `host` は文字列（例: `"127.0.0.1"`）または `{a, b, c, d}` のタプル。
  ソケットはアクティブモードで、データは `{:tcp, sock, data}` / `{:tcp_closed, sock}` で届く。

  ## Example

      {:ok, sock} = ExTCP.connect_stream("127.0.0.1", 40001)
      ExTCP.loop(%ExTCP.TcpState{socket: sock, phase: :status, parse_fn: &parse/1})
  """
  def connect_stream(host, port, opts \\ []) do
    host_connect = if is_binary(host), do: String.to_charlist(host), else: host
    default_opts = [active: true, mode: :binary]
    :gen_tcp.connect(host_connect, port, Keyword.merge(default_opts, opts))
  end

  @doc """
  任意の IPv4 宛に 3 way handshakeしてデータ送信する（Raw ソケット。loop には connect_stream を使う）
  """
  def connect(
        dst_ip \\ @ip,
        dst_port \\ @dst_port,
        src_ip \\ @ip,
        src_port \\ @src_port,
        timeout_ms \\ 100_000
      ) do
    {:ok, sock} = :socket.open(:inet, :raw, :tcp)
    :ok = :socket.setopt(sock, :ip, :hdrincl, true)

    # Initial Send Sequence
    iss = :rand.uniform(0x7FFFFFFF)

    send_syn(sock, src_ip, src_port, dst_ip, dst_port, iss)

    deadline = System.monotonic_time(:millisecond) + timeout_ms

    flow = {src_ip, src_port, dst_ip, dst_port}
    {:ok, pkt} = wait_segment(sock, @syn_ack, flow, deadline)

    seq = iss + 1
    ack = pkt.seq + 1

    send_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, ack)

    IO.puts("Done 3 way-handshake")

    IO.puts("HTTP request")
    req = "GET / HTTP/1.0\r\n\r\n"
    send_psh_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, ack, req)

    seq = seq + byte_size(req)

    case wait_segment(sock, @ack, flow, deadline) do
      {:ok, ack_pkt} ->
        IO.puts("Receiving HTTP response")
        File.write!("out", "")
        final_ack = receive_all_response_packets(sock, flow, deadline, seq, ack_pkt.seq)

        send_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, final_ack)

        close_connection(sock, src_ip, src_port, dst_ip, dst_port, seq, final_ack, flow)

      {:error, reason} ->
        IO.puts("ACK wait error: #{inspect(reason)}")
        :socket.close(sock)
        {:error, reason}
    end
  end

  defp receive_all_response_packets(sock, {src_ip, src_port, dst_ip, dst_port} = flow, deadline_ms, my_seq, server_seq) do
    short_deadline = System.monotonic_time(:millisecond) + 1000

    case wait_segment(sock, @psh_ack, flow, short_deadline) do
      {:ok, pkt} ->
        IO.puts("Received payload (hex dump):")
        File.write!("out", Base.encode16(pkt.payload, case: :lower) <> "\n", [:append])
        IO.puts("")

        new_server_seq = pkt.seq + byte_size(pkt.payload)
        send_ack(sock, src_ip, src_port, dst_ip, dst_port, my_seq, new_server_seq)
        receive_all_response_packets(sock, flow, deadline_ms, my_seq, new_server_seq)

      {:error, _} ->
        case wait_segment(sock, @fin_psh_ack, flow, short_deadline) do
          {:ok, pkt} ->
            IO.puts("Received payload (hex dump):")
            File.write!("out", Base.encode16(pkt.payload, case: :lower) <> "\n", [:append])
            IO.puts("")

            new_server_seq = pkt.seq + byte_size(pkt.payload)
            send_ack(sock, src_ip, src_port, dst_ip, dst_port, my_seq, new_server_seq)
            new_server_seq

          {:error, _} ->
            server_seq
        end
    end
  end

  defp close_connection(sock, src_ip, src_port, dst_ip, dst_port, seq, ack, flow) do
    IO.puts("Send FIN+ACK")
    send_fin_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, ack)
    seq = seq + 1

    IO.puts("Waiting for server ACK (confirm FIN+ACK)")
    short_fin_deadline = System.monotonic_time(:millisecond) + 2000

    case wait_segment(sock, @ack, flow, short_fin_deadline) do
      {:ok, ack_pkt} ->
        case wait_segment(sock, @fin_psh_ack, flow, short_fin_deadline) do
          {:ok, finpkt} ->
            ack = finpkt.seq + byte_size(finpkt.payload)
            send_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, ack)
            :socket.close(sock)
            :ok

          {:error, _} ->
            case wait_segment(sock, @fin_ack, flow, short_fin_deadline) do
              {:ok, finpkt} ->
                ack = finpkt.seq + 1
                send_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, ack)
                :socket.close(sock)
                :ok

              {:error, _} ->
                case wait_segment(sock, @fin, flow, short_fin_deadline) do
                  {:ok, finpkt} ->
                    ack = finpkt.seq + 1
                    send_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, ack)
                    :socket.close(sock)
                    :ok

                  {:error, reason} ->
                    IO.puts("FIN wait error: #{inspect(reason)} - closing socket")
                    :socket.close(sock)
                    :ok
                end
            end
        end

      {:error, _} ->
        IO.puts("ACK not received; waiting for FIN+PSH+ACK directly...")

        case wait_segment(sock, @fin_psh_ack, flow, short_fin_deadline) do
          {:ok, finpkt} ->
            IO.puts("FIN+PSH+ACK received: seq=#{finpkt.seq}")
            ack = finpkt.seq + byte_size(finpkt.payload)
            send_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, ack)
            :socket.close(sock)
            :ok

          {:error, _} ->
            case wait_segment(sock, @fin_ack, flow, short_fin_deadline) do
              {:ok, finpkt} ->
                IO.puts("FIN+ACK received: seq=#{finpkt.seq}")
                ack = finpkt.seq + 1
                send_ack(sock, src_ip, src_port, dst_ip, dst_port, seq, ack)
                :socket.close(sock)
                :ok

              {:error, reason} ->
                IO.puts("FIN wait error: #{inspect(reason)} - closing socket")
                :socket.close(sock)
                :ok
            end
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

  defp wait_segment(sock, flags, {src_ip, sp, dst_ip, dp} = flow, deadline_ms) do
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
