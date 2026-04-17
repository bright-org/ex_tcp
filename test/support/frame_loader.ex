defmodule FrameLoader do
  import Bitwise

  def read_data_file(file_path) do
    File.stream!(file_path)
    |> Enum.reduce({[], <<>>}, fn line, {packets, current_packet} ->
      line
      |> String.trim()
      |> String.to_integer(16)
      |> handle_line(current_packet, packets)
    end)
    |> elem(0)
    |> Enum.reverse()
  end

  defp handle_line(value, current_packet, packets) do
    # bit9 は無効データ(Elixirでは読み飛ばし)
    if (value &&& 0x200) != 0 do
      {packets, current_packet}
    else
      data = <<value &&& 0xFF::8>>
      # bit8 はパケット末尾
      if (value &&& 0x100) != 0 do
        {[current_packet <> data | packets], <<>>}
      else
        {packets, current_packet <> data}
      end
    end
  end
end
