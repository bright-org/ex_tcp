defmodule ExTCP.PHYTest do
  use ExUnit.Case, async: true

  use ExUnit.Case, async: true
  alias ExTCP.PHY

  @tag :crc
  test "CRC32 known vector '123456789' == 0xCBF43926" do
    data = "123456789"
    expected = 0xCBF43926
    result = PHY.crc32_eth(data)

    assert result == expected,
           "Expected 0x#{Integer.to_string(expected, 16)}, got 0x#{Integer.to_string(result, 16)}"
  end

  test "hoge" do
    expect =
      FrameLoader.read_data_file("test/support/input_data_ok.txt") |> hd()

    l2 =
      expect
      |> ExTCP.PHY.normalize()

    crc = PHY.crc32_eth(l2)
    bin = ExTCP.PHY.encapsulate(l2, preamble: true, fcs: true)

    assert bin == expect
    assert binary_part(bin, byte_size(bin) - 4, 4) == <<crc::little-32>>
  end
end
