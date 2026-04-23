defmodule ExTCP.Host do
  use GenServer
  alias ExTCP.{Frame, Tcp}

  @python "python3"
  @tap "tap1"

  require Logger

  def start_link(_) do
    GenServer.start_link(__MODULE__, %{}, name: __MODULE__)
  end

  def init(_) do
    python =
      System.find_executable(@python) ||
        raise "python executable #{@python} not found in PATH"

    tap_port =
      :ex_tcp
      |> :code.priv_dir()
      |> to_string()
      |> Path.join("tap_port.py")

    port =
      Port.open(
        {:spawn_executable, String.to_charlist(python)},
        [
          :binary,
          :exit_status,
          args: [String.to_charlist(tap_port), @tap]
        ]
      )

    iss = :rand.uniform(0x7FFFFFFF)

    {:ok, %{port: port, iss: iss, irs: nil, snd_nxt: iss + 1, rcv_nxt: 0}}
  end

  def handle_info({port, {:data, data}}, %{port: port, iss: iss} = state) do
    case ExTCP.Ether.reply(data, iss) do
      nil ->
        IO.puts("[HOST DO NOTHING]")
        {:noreply, state}

      %{frame: frame, seq: _seq} ->
        Port.command(state.port, frame)
        IO.puts("[HOST TX SYN-ACK]")
        {:noreply, state}
    end
  end

  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    require Logger
    Logger.error("Port #{inspect(port)} exited with status #{status}")
    {:stop, {:port_exit, status}, state}
  end

  require Logger

  # どこかで spawn_monitor / Task.Supervisor を使っている前提
  def handle_info({:DOWN, _ref, :process, _pid, {reason, stack}}, state) do
    Logger.error("""
    worker crashed:
    #{Exception.format(:error, reason, stack)}
    """)

    {:noreply, state}
  end
end
