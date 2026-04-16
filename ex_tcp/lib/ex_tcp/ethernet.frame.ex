defmodule ExTCP.Ethernet.Frame do
  @preamble <<0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xD5>>

  @ethertype_ipv4 0x0800

  @moduledoc """
  Ethernet II フレームを表す構造体。

  各フィールド:
    * `:dst` - 宛先MACアドレス（例: `"ff:ff:ff:ff:ff:ff"`）
    * `:src` - 送信元MACアドレス（例: `"00:11:22:33:44:55"`）
    * `:type` - EtherTypeを16進文字列で保持（例: `"0x0800"`）
    * `:payload_size` - ペイロード長（バイト数）
    * `:payload` - 実際のペイロードバイナリ
  """

  defstruct [
    :dst,
    :src,
    :type,
    :payload_size,
    :payload
  ]

  @type t :: %__MODULE__{
          dst: String.t(),
          src: String.t(),
          type: String.t(),
          payload_size: non_neg_integer(),
          payload: binary()
        }
  @doc """
  Ethernetフレームを解析し、`ExTCP.Ethernet`構造体を返す。

  ## 例
      iex> ExTCP.Ethernet.parse!(<<0xff,0xff,0xff,0xff,0xff,0xff,0x00,0x11,0x22,0x33,0x44,0x55,0x08,0x00, "data">>)
      %ExTCP.Ethernet{
        dst: "ff:ff:ff:ff:ff:ff",
        src: "00:11:22:33:44:55",
        type: "0x800",
        payload_size: 4,
        payload: "data"
      }
  """
  def parse!(<<dst::binary-size(6), src::binary-size(6), type::16, payload::binary>>, opts \\ []) do
    %__MODULE__{
      dst: mac(dst),
      src: mac(src),
      type: "0x" <> Integer.to_string(type, 16),
      payload_size: byte_size(payload),
      payload: payload
    }
  end

  @doc """
    宛先アドレスと送信元アドレスを入れ替える
  """
  def swap_addrs(%__MODULE__{dst: dst, src: src} = received_frame) do
    %__MODULE__{received_frame | dst: src, src: dst}
  end

  def build(%__MODULE__{} = frame, packet) do
    dst_bin = mac_to_bin(frame.dst)
    src_bin = mac_to_bin(frame.src)
    type_int = parse_type(frame.type)

    <<
      dst_bin::binary-size(6),
      src_bin::binary-size(6),
      type_int::16,
      packet::binary
    >>
    |> zero_padding()
  end

  def build({dst_mac_str, src_mac_str}, packet, opts \\ []) do

    dst_mac = ExTCP.Utils.mac_bin(dst_mac_str)
    # 自ノードのMAC
    src_mac = ExTCP.Utils.mac_bin(src_mac_str)
    # IPv4 (EtherType)
    eth_type = <<0x08, 0x00>>

    base = dst_mac <> src_mac <> eth_type <> packet

    with_preamble? = Keyword.get(opts, :with_preamble, false)
    with_fcs? = Keyword.get(opts, :with_fcs, false)
    base = if with_fcs?, do: base <> ExTCP.FCS.fcs_bytes(base), else: base
    if with_preamble?, do: @preamble <> base, else: base
  end

  defp zero_padding(frame) do
    frame =
      if byte_size(frame) < 60 do
        frame <> :binary.copy(<<0>>, 65 - byte_size(frame))
      else
        frame
      end
  end

  defp mac(<<a, b, c, d, e, f>>) do
    Enum.map_join(
      [a, b, c, d, e, f],
      ":",
      &(Integer.to_string(&1, 16) |> String.pad_leading(2, "0"))
    )
  end

  # "AA:BB:CC:DD:EE:FF" → <<0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
  defp mac_to_bin(mac_str) when is_binary(mac_str) do
    mac_str
    |> String.split(":")
    |> Enum.map(&String.to_integer(&1, 16))
    |> :binary.list_to_bin()
  end

  # "0x0800" or 0x0800 → 0x0800
  defp parse_type("0x" <> hex), do: String.to_integer(hex, 16)
  defp parse_type(int) when is_integer(int), do: int
end
