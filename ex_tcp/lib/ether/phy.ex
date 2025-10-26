defmodule Ether.PHY do
  @moduledoc "L1相当の前処理: preamble/SFD と FCS を剥がして L2 を渡す"
  @preamble <<0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55>>
  @sfd 0xD5
  # Ethernet最小ペイロード+ヘッダ（FCS除く）
  @min_eth_no_fcs 60
  @fcs_len 4

  import Bitwise

  @doc """
  L2フレーム（[dst(6)][src(6)][ethertype(2)][payload...]）に対し、
  オプションで preamble/SFD と FCS を付与する。

  ## Options
    * `:preamble` - true/false（既定: true）
    * `:fcs`      - true/false（既定: true）

  ## Returns
    * バイナリ: [preamble*7][SFD][L2 frame][FCS(4B little-endian)]
      （オプションにより前後の付与は省略）
  """
  def encapsulate(l2_frame, opts \\ []) when is_binary(l2_frame) do
    pre? = Keyword.get(opts, :preamble, true)
    fcs? = Keyword.get(opts, :fcs, true)

    with_fcs =
      if fcs?, do: l2_frame <> fcs_bytes(l2_frame), else: l2_frame

    if pre? do
      <<@preamble::binary, @sfd, with_fcs::binary>>
    else
      with_fcs
    end
  end

  # ---------- CRC-32/Ethernet (reflected) ----------

  @crc32_table (for i <- 0..255 do
                  Enum.reduce(0..7, i, fn _, c ->
                    if (c &&& 1) == 1, do: 0xEDB88320 ^^^ (c >>> 1), else: c >>> 1
                  end)
                end)
               |> :erlang.list_to_tuple()

  defp fcs_bytes(data) do
    crc = crc32_eth(data)
    # EthernetはLSBファーストで送る（リトルエンディアン）
    <<crc::little-32>>
  end

  def crc32_eth(bin) when is_binary(bin) do
    Enum.reduce(:binary.bin_to_list(bin), 0xFFFF_FFFF, fn byte, acc ->
      idx = Bitwise.band(Bitwise.bxor(acc, byte), 0xFF)
      tbl = elem(@crc32_table, idx)

      # 論理右シフト相当（算術シフトだと負数扱いになるため明示マスク）
      acc_shr = Bitwise.band(Bitwise.bsr(acc, 8), 0x00FF_FFFF)

      Bitwise.band(Bitwise.bxor(acc_shr, tbl), 0xFFFF_FFFF)
    end)
    |> Bitwise.bxor(0xFFFF_FFFF)
    |> Bitwise.band(0xFFFF_FFFF)
  end

  @doc """
  原始バイト列から preamble/SFD と FCS を必要に応じて剥がす。
  戻り値は L2 フレーム (dst/src/ethertype から始まる) を想定。
  """
  def normalize(raw) when is_binary(raw) do
    raw
    |> maybe_strip_preamble()
    |> maybe_strip_fcs()
  end

  # 先頭が 55*7 + D5 なら剥がす
  defp maybe_strip_preamble(<<@preamble::binary, @sfd, rest::binary>>), do: rest
  defp maybe_strip_preamble(other), do: other

  # 末尾にFCS(4B)がありそうなら剥がす（環境に応じて切替可能）
  # ここでは簡易ヒューリスティック: フレーム長が十分あり、かつ
  # 一般にTAPでは付かないので、「明らかに生PHY入力」経路のみ有効化して使う想定。
  defp maybe_strip_fcs(bin) do
    if has_fcs?(bin) do
      binary_part(bin, 0, byte_size(bin) - @fcs_len)
    else
      bin
    end
  end

  # 最低長や運用フラグで制御。必要なら CRC-32 の検証も実装可能
  defp has_fcs?(bin) do
    byte_size(bin) >= @min_eth_no_fcs + @fcs_len
  end
end
