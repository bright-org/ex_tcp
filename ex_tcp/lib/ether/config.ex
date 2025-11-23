defmodule Ether.Config do
  @enforce_keys [:src_ip, :dst_ip, :src_mac, :dst_mac, :proto]
  defstruct [:src_ip, :dst_ip, :src_mac, :dst_mac, :proto, preamble?: false]

  @type t :: %__MODULE__{}

  @spec new(keyword()) :: t()
  def new(opts) do
    %__MODULE__{
      src_ip: Keyword.fetch!(opts, :src_ip),
      dst_ip: Keyword.fetch!(opts, :dst_ip),
      src_mac: Keyword.fetch!(opts, :src_mac),
      dst_mac: Keyword.fetch!(opts, :dst_mac),
      proto: :tcp,
      preamble?: Keyword.get(opts, :preamble?, false)
    }
  end
end
