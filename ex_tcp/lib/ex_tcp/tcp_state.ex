defmodule ExTCP.TcpState do
  defstruct socket: nil, phase: nil, buffer: <<>>, parse_fn: nil, body: nil
end
