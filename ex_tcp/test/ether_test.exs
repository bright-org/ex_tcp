defmodule EtherTest do
  use ExUnit.Case, async: true

  alias Ether.Config
  @dst_mac <<0x02, 0x00, 0x00, 0x00, 0x01, 0xAA>>
  @src_mac <<0x02, 0x00, 0x00, 0x00, 0x01, 0xBB>>

  test "build/2 adds PHY preamble when preamble? is true" do
    cfg =
      Config.new(
        src_ip: {10, 0, 0, 1},
        dst_ip: {10, 0, 0, 2},
        src_mac: @src_mac,
        dst_mac: @dst_mac,
        preamble?: true
      )

    payload = <<"dummy tcp segment">>

    frame = Ether.build(payload, cfg)

    assert <<0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0xD5, _rest::binary>> = frame
  end
end
