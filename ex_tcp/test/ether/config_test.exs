defmodule Ether.ConfigTest do
  use ExUnit.Case, async: true

  alias Ether.Config

  @dst_mac <<0x02, 0x00, 0x00, 0x00, 0x01, 0xAA>>
  @src_mac <<0x02, 0x00, 0x00, 0x00, 0x01, 0xBB>>

  describe "new/1" do
    test "builds tcp/ipv4 config struct with defaults" do
      cfg =
        Config.new(
          src_ip: {10, 0, 0, 1},
          dst_ip: {10, 0, 0, 2},
          src_mac: <<0x02, 0x00, 0x00, 0x00, 0x01, 0xAA>>,
          dst_mac: <<0x02, 0x00, 0x00, 0x00, 0x01, 0xBB>>
        )

      assert %Config{} = cfg
      assert cfg.src_ip == {10, 0, 0, 1}
      assert cfg.dst_ip == {10, 0, 0, 2}
      assert cfg.proto == :tcp
      assert cfg.preamble? == false
    end
  end
end
