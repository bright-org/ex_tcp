defmodule ExTCP.Ipv4 do
  import Bitwise
  alias ExTCP.Utils

  alias ExTCP.{Ipv4, TCP}
  # defstruct src_ip

  require Logger

  def wrap(nil, _, _), do: nil

  def wrap(tcp_wo_csum, src_ip, dst_ip, payload \\ <<>>) do
    tcp_csum = TCP.checksum(src_ip, dst_ip, tcp_wo_csum <> payload)

    ip_csum = build(src_ip, dst_ip, 20 + byte_size(tcp_csum) + byte_size(payload))

    ip_csum <> tcp_csum <> payload
  end

  ## ===== IPv4: 20B 固定ヘッダ（IP_HDRINCL 前提）=====
  def build({a, b, c, d}, {e, f, g, h}, tot) do
    ver_ihl = (4 <<< 4) + 5
    tos = 0
    ttl = 64
    id = 0x2D_D5

    # DF
    flags_frag = 1 <<< 14
    # proto=6(TCP)
    base =
      <<ver_ihl, tos, tot::16, id::16, flags_frag::16, ttl, 6, 0::16, a, b, c, d, e, f, g, h>>

    sum = Utils.csum16(base)
    <<ver_ihl, tos, tot::16, id::16, flags_frag::16, ttl, 6, sum::16, a, b, c, d, e, f, g, h>>
  end

  def parse!(packet) do
    Logger.debug("IPv4.parse! packet (hex): #{Base.encode16(packet)}")

    packet
    |> parse()
    |> case do
      {:ok, decode} -> decode
      :error -> raise "Ipv4 parse failed"
    end
  end

  def parse(<<
        _ver::4,
        hl::4,
        _tos::8,
        _total_length::16,
        _id::16,
        _ff::16,
        _ttl::8,
        proto::8,
        _check_sumsum::16,
        s1,
        s2,
        s3,
        s4,
        d1,
        d2,
        d3,
        d4,
        rest::binary
      >>) do
    ihl = hl * 4
    opt = max(ihl - 20, 0)

    case rest do
      <<_opts::binary-size(opt), tcp::binary>> ->
        {:ok, {{s1, s2, s3, s4}, {d1, d2, d3, d4}, proto, tcp}}

      _ ->
        :error
    end
  end

  def parse(_), do: :error
end
