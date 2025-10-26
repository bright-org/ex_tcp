defmodule Ether.Host do
  use GenServer
  alias Ether.{Frame, Tcp}

  @python "python3"
  @tap "tap1"

  def start_link(_) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(_) do
    port = Port.open({:spawn, "#{@python} tap_port.py #{@tap}"}, [:binary, :exit_status])
    iss = :rand.uniform(0x7FFFFFFF)

    {:ok, %{port: port, iss: iss, irs: nil, snd_nxt: iss + 1, rcv_nxt: 0}}
  end

  def handle_info({port, {:data, data}}, %{port: port, iss: iss} = state) do
    case Ether.reply(data, iss) do
      nil ->
        IO.puts("[HOST DO NOTHING]")
        {:noreply, state}

      %{frame: frame, seq: _seq} ->
        Port.command(state.port, frame)
        IO.puts("[HOST TX SYN-ACK]")
        {:noreply, state}
    end
  end
end
