defmodule Ether do
  alias Ether.{Config, Ethernet.Frame, Ipv4, TCP}

  @tap0 {10, 0, 0, 1}
  @tap0_port 12345
  @tap1 {10, 0, 0, 2}
  @tap1_port 80

  def reply(frame, seq) do
    %{eth: eth, ip: ip, tcp: tcp} = parse!(frame)

    {src_ip, dst_ip, proto, _} = ip

    if validate(ip) do
      IO.puts("FROM LOCAL NIC")

      packet =
        tcp
        |> TCP.swap_addrs()
        |> TCP.reply(seq)
        |> Ipv4.wrap(dst_ip, src_ip)

      if is_nil(packet) do
        nil
      else
        frame =
          eth
          |> Frame.swap_addrs()
          |> Frame.build(packet)

        %{frame: frame, seq: tcp.seq, payload: tcp.rest}
      end
    else
      nil
    end
  end

  def validate({@tap0, @tap1, _, _}), do: true
  def validate({@tap1, @tap0, _, _}), do: true
  def validate(_), do: false

  def parse!(frame) do
    eth = Frame.parse!(frame)
    ip = {_, _, _, payload} = Ipv4.parse!(eth.payload)
    tcp = TCP.parse!(payload)

    %{eth: eth, ip: ip, tcp: tcp}
  end

  @doc """
  L4 Payload: TCP or UDP (Currently supports only TCP)
  """
  @spec build(binary(), Config.t()) :: binary()
  def build(l4_payload, %Config{} = cfg) do
    ip = Ipv4.wrap(l4_payload, cfg.src_ip, cfg.dst_ip)
    frame = Frame.build({cfg.dst_mac, cfg.src_mac}, ip)

    if cfg.preamble? do
      Ether.PHY.encapsulate(frame, preamble: true, fcs: true)
    else
      frame
    end
  end
end
