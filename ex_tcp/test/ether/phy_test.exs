defmodule Ether.PHYTest do
  use ExUnit.Case, async: true

  use ExUnit.Case, async: true
  alias Ether.PHY

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
      <<85, 85, 85, 85, 85, 85, 85, 213, 255, 255, 255, 255, 255, 255, 28, 192, 53, 1, 162, 159,
        8, 6, 0, 1, 8, 0, 6, 4, 0, 1, 28, 192, 53, 1, 162, 159, 169, 254, 166, 124, 0, 0, 0, 0, 0,
        0, 169, 254, 179, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 158, 96,
        187>>

    l2 =
      Ether.Local.read_data_file("test/support/input_data_ok.txt")
      |> hd()
      |> Ether.PHY.normalize()

    crc = PHY.crc32_eth(l2)
    bin = Ether.PHY.encapsulate(l2, preamble: true, fcs: true)

    assert bin == expect
    assert binary_part(bin, byte_size(bin) - 4, 4) == <<crc::little-32>>

    IO.inspect(expect, binaries: :as_binaries, limit: :infinity)
    IO.inspect(bin, binaries: :as_binaries, limit: :infinity)

  end
end
