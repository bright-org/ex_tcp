defmodule Ether.TCP do
  import Bitwise
  alias Ether.{Ipv4, Utils}

  @ipproto_tcp 6

  # @fin 0x01
  @syn 0x02
  @psh 0x08
  # @rst 0x04
  @ack 0x10
  @syn_ack @syn ||| @ack
  @psh_ack 0x18
  # @urg 0x20

  def syn?(f), do: (f &&& @syn) != 0
  def psh?(f), do: (f &&& @psh) != 0
  def ack?(f), do: (f &&& @ack) != 0
  def syn_ack?(f), do: (f &&& (@syn ||| @ack)) == (@syn ||| @ack)
  # def psh_ack?(f), do: (f &&& (@syn ||| @psh)) == (@syn ||| @psh)
  def psh_ack?(f), do: (f &&& @psh_ack) == @psh_ack

  def parse!(
        <<sp::16, dp::16, seq::32, ack::32, doff_flags, flags, _wnd::16, _::16, _::16,
          rest::binary>>
      ) do
    %{sp: sp, dp: dp, seq: seq, ack: ack, hlen: (doff_flags >>> 4) * 4, flags: flags, rest: rest}
  end

  def reply(frame, seq) do
    %{sp: sp, dp: dp, seq: remote_seq, ack: ack, hlen: hlen, flags: flags, rest: rest} = frame

    cond do
      syn_ack?(flags) ->
        IO.puts("SYN-ACK")
        ack(sp, dp, seq, remote_seq)

      syn?(flags) ->
        IO.puts("SYN")
        syn_ack(sp, dp, seq, 0)

      psh_ack?(flags) ->
        IO.puts("PSH_ACK")
        IO.puts(rest)
        nil

      ack?(flags) ->
        IO.puts("ACK")
        nil

      true ->
        IO.puts("Cannot reach here.")
    end
  end

  def syn(src_port, dst_port, local_iss, window \\ 65_535) do
    build(src_port, dst_port, local_iss, 0, @syn, window)
  end

  def syn_ack(src_port, dst_port, local_iss, remote_seq \\ 0, window \\ 65_535) do
    seq = local_iss
    ack = remote_seq + 1
    build(src_port, dst_port, seq, ack, @syn_ack, window)
  end

  def ack(src_port, dst_port, local_iss, remote_seq \\ 0, window \\ 65_535) do
    build(src_port, dst_port, local_iss, remote_seq, @ack, window)
  end

  def psh_ack(src_port, dst_port, local_iss, remote_seq \\ 0, window \\ 65_535) do
    build(src_port, dst_port, local_iss, remote_seq, @psh_ack, window)
  end

  defp build(
         src_port,
         dst_port,
         seq,
         ack,
         flags,
         window \\ 65_535
       ) do
    doff = 5

    <<
      src_port::16,
      dst_port::16,
      seq::32,
      ack::32,
      (doff <<< 12) + flags::16,
      window::16,
      0::16,
      0::16
    >>
  end

  def checksum({a, b, c, d} = src_ip, {e, f, g, h} = dst_ip, tcp_seg) do
    pseudo = <<a, b, c, d, e, f, g, h, 0, @ipproto_tcp, byte_size(tcp_seg)::16>>
    csum = Utils.csum16(pseudo <> tcp_seg)
    :binary.part(tcp_seg, 0, 16) <> <<csum::16>> <> <<0::16>>
  end

  def swap_addrs(%{sp: sp, dp: dp} = tcp) do
    %{tcp | sp: dp, dp: sp}
  end
end
