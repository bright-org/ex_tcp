defmodule Ether do
  alias Ether.{Ethernet.Frame, Ipv4, TCP}

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

        %{frame: frame, seq: tcp.seq}
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
end
