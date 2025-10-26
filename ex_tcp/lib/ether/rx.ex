defmodule Ether.Rx do
  alias Ether.Frame

  @type_ipv4 0x0800
  @type_arp 0x0806

  def handle_frame(<<dst::binary-size(6), src::binary-size(6), type::16, payload::binary>>) do
    case type do
      @type_ipv4 ->
        parse_ipv4(payload)

      @type_arp ->
        IO.puts("ARP frame received")

      _ ->
        :ignore
    end
  end

  defp parse_ipv4(<<4::4, _ihl::4, _rest::binary>> = packet) do
    IO.puts("[Elixir] IPv4 frame received (#{byte_size(packet)} bytes)")
  end
end
