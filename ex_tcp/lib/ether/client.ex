defmodule Ether.Client do
  use GenServer

  alias Ether.{Client, Ipv4, TCP}
  alias Ether.Ethernet.Frame

  @python "python3"
  @tap "tap0"

  @tap0 {10, 0, 0, 1}
  @tap0_port 12345
  @tap1 {10, 0, 0, 2}
  @tap1_port 80

  @dst_mac "02:00:00:00:01:aa"
  @src_mac "02:00:00:00:01:bb"

  def start_link(_), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  # 3 way handshake開始時に利用
  def send_syn(), do: GenServer.cast(__MODULE__, :send_syn)

  # 3 way handshake後の任意メッセージ送信
  def send_frame(data), do: GenServer.cast(__MODULE__, {:send, data})

  def register_consumer(pid \\ self()),
    do: GenServer.cast(__MODULE__, {:register_consumer, pid})

  defp maybe_deliver_payload(nil, _data), do: :ok

  defp maybe_deliver_payload(consumer, data) do
    send(consumer, {:ether_payload, data})
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

    {:ok, %{port: port, iss: iss, irs: nil, snd_nxt: iss + 1, rcv_nxt: 0, consumer: nil}}
  end

  def handle_cast({:register_consumer, pid}, state) do
    {:noreply, %{state | consumer: pid}}
  end

  def handle_cast(:send_syn, %{port: port, iss: iss} = state) do
    packet =
      TCP.syn(@tap0_port, @tap1_port, iss)
      |> Ipv4.wrap(@tap0, @tap1)

    frame = Frame.build({@dst_mac, @src_mac}, packet)

    Port.command(port, frame)
    IO.puts("[TX SYN] ISS=#{iss}")
    {:noreply, %{state | snd_nxt: iss + 1}}
  end

  def handle_cast({:send, payload}, %{port: port, snd_nxt: snd_nxt, rcv_nxt: rcv_nxt} = state) do
    packet =
      TCP.psh_ack(@tap0_port, @tap1_port, snd_nxt, rcv_nxt)
      |> Ipv4.wrap(@tap0, @tap1, payload)

    frame =
      Frame.build({@dst_mac, @src_mac}, packet)

    Port.command(port, frame)
    {:noreply, state}
  end

  # フレーム受信時処理
  def handle_info({port, {:data, data}}, %{port: port, snd_nxt: snd_nxt} = state) do
    case Ether.reply(data, snd_nxt) do
      nil ->
        IO.puts("[DO NOTHING]")
        {:noreply, state}

      %{frame: frame, seq: remote_seq, payload: app_data} ->
        Port.command(state.port, frame)
        IO.puts("[CLIENT REPLY]")
        maybe_deliver_payload(state.consumer, app_data)
        {:noreply, %{state | irs: remote_seq}}
    end
  end

  def handle_info({port, {:exit_status, status}}, %{port: port} = state) do
    require Logger
    Logger.error("Port #{inspect(port)} exited with status #{status}")
    {:stop, {:port_exit, status}, state}
  end
end
