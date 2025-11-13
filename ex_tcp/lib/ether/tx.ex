defmodule Ether.Transmitter do
  alias Ether.{Frame, Client, Ipv4, TCP}

  @tap0 {10, 0, 0, 1}
  @tap0_port 12345
  @tap1 {10, 0, 0, 2}
  @tap1_port 80

  def send_syn do
    iss = :rand.uniform(0x7FFFFFFF)

    packet = TCP.syn(@tap0_port, @tap1_port, iss)
      |> Ipv4.wrap(@tap0, @tap1)

    frame = hoge(packet)

    Client.send_frame(frame)
  end

  def send(frame) do

  end

  defp hoge(ipv4_payload) do
    dst_mac = Ether.Utils.mac_bin("ff:ff:ff:ff:ff:ff")   # 宛先（ARP未実装なので一旦broadcast）
    src_mac = Ether.Utils.mac_bin("76:bf:c9:f8:4b:31")   # 自ノードのMAC
    eth_type = <<0x08, 0x00>>                            # IPv4 (EtherType)

    dst_mac <> src_mac <> eth_type <> ipv4_payload
  end
end
