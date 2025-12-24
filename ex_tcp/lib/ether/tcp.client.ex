defmodule Ether.TCP.Client do
  use GenServer

  # Public API

  # 例: Ether.Client.start_link(remote_ip: {192,168,50,239}, remote_port: 5000, local_port: 0)
  # local_port: 0 ならOSにエフェメラル(任意)割当を任せます
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  def send(bin) when is_binary(bin) do
    GenServer.call(__MODULE__, {:send, bin})
  end

  def close(), do: GenServer.stop(__MODULE__, :normal)

  # GenServer

  @impl true
  def init(opts) do
    remote_ip = Keyword.fetch!(opts, :remote_ip)
    remote_port = Keyword.fetch!(opts, :remote_port)
    local_port = Keyword.get(opts, :local_port, 0)

    with {:ok, sock} <- :socket.open(:inet, :stream, :tcp),
         :ok <- maybe_bind(sock, local_port),
         :ok <- :socket.connect(sock, %{family: :inet, addr: remote_ip, port: remote_port}) do

      {:ok, %{sock: sock}}
    else
      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_call({:send, bin}, _from, %{sock: sock} = state) do
    case :socket.send(sock, bin) do
      :ok -> {:reply, :ok, state}
      {:error, reason} -> {:reply, {:error, reason}, state}
    end
  end

    # ---- internals --------------------------------------------------

    defp maybe_bind(_sock, 0), do: :ok
    defp maybe_bind(sock, port),
      do: :socket.bind(sock, %{family: :inet, addr: {0,0,0,0}, port: port})
end
