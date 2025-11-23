defmodule Ether.Utils do
  import Bitwise

  def mac_bin(<<_::48>> = mac), do: mac

  # "AA:BB:CC:DD:EE:FF" → <<0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
  def mac_bin(mac_str) when is_binary(mac_str) do
    mac_str
    |> String.split(":")
    |> Enum.map(&String.to_integer(&1, 16))
    |> :binary.list_to_bin()
  end

  def csum16(bin) when is_binary(bin) do
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
end
