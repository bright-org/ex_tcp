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

  ## ===== 16bit 1の補数チェックサム =====
  import Bitwise

  ## ===== 公開 API =====

  @ip {127, 0, 0, 1}
  @src_port 40000
  @dst_port 40001

  @doc """
  任意の IPv4 宛に 3 way handshakeしてデータ送信する
  """
  def connect(
        dst_ip \\ @ip,
        dst_port \\ @dst_port,
        src_ip \\ @ip,
        src_port \\ @src_port,
        timeout_ms \\ 100_000
      ) do
    # 送信用
    {:ok, tx} =
      with {:ok, s} <- :socket.open(:inet, :raw, 6),
           :ok <- :socket.setopt(s, :ip, :hdrincl, true) do
        {:ok, s}
      end

    # 受信用
    {:ok, rx} = :socket.open(:inet, :raw, 6)

    # Initial Send Sequence
    iss = :rand.uniform(0x7FFFFFFF)

    send_syn(tx, src_ip, src_port, dst_ip, dst_port, iss)

    deadline = System.monotonic_time(:millisecond) + timeout_ms

    wait_synack(rx, src_ip, src_port, dst_ip, dst_port, deadline)
    |> case do
      {:ok, :synack, s_isn} ->
        seq = iss + 1
        ack = s_isn + 1

        send_ack(tx, src_ip, src_port, dst_ip, dst_port, seq, ack)
        send_psh_ack(tx, src_ip, src_port, dst_ip, dst_port, seq, ack, "hello\n")
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

  defp wait_synack(sock, src_ip, sp, dst_ip, dp, deadline_ms) do
    now = System.monotonic_time(:millisecond)

    if now >= deadline_ms do
      {:error, :timeout}
    else
      # 1回のrecvに残り時間をそのまま渡す（select発生でもスピンしにくくする）

      :socket.recv(sock)
      |> case do
        {:ok, bin} ->
          bin
          |> Ipv4.parse()
          |> case do
            {:ok, {^dst_ip, ^src_ip, _proto, tcp_bin}} ->
              tcp_bin
              |> parse_tcp()
              |> case do
                # 最終判定：SYN+ACK（0x12）か
                %{sp: spv, dp: dpv, flags: fl, seq: rseq} = pkt ->
                  IO.puts("TCP #{spv}->#{dpv} flags=0x#{Integer.to_string(fl, 16)}")

                  if spv == dp and dpv == sp and (fl &&& 0x12) == 0x12 do
                    {:ok, :synack, pkt.seq}
                  else
                    wait_synack(sock, src_ip, sp, dst_ip, dp, deadline_ms)
                  end

                # デバッグ/混線時の観測: アドレス/ポートは合うがSYN+ACKではない（例：反射SYN）
                %{sp: ^dp, dp: ^sp} ->
                  wait_synack(sock, src_ip, sp, dst_ip, dp, deadline_ms)

                _ ->
                  wait_synack(sock, src_ip, sp, dst_ip, dp, deadline_ms)
              end

            {:ok, _} ->
              wait_synack(sock, src_ip, sp, dst_ip, dp, deadline_ms)

            :error ->
              {:error, "Unexpected error"}
          end

        {:select, _} ->
          {:error, :timeout}

        other ->
          other
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
           _rest::binary>>
       ) do
    %{sp: sp, dp: dp, seq: seq, ack: ack, hlen: (doff_flags >>> 4) * 4, flags: flags}
  end
end
