defmodule ExTCP.StreamParseState do
  @moduledoc """
  バイトストリーム（例: TCP ペイロード）をプロトコルに応じて解析する際の状態を保持する構造体。

  トランスポート層（TCP など）の上で、受信したバイト列を buffer に蓄積し、
  `parse_fn` で上位プロトコル（HTTP / Slack など）に応じた解析を行う。
  ExTCP は終了判定に `phase` を使わず、parse_fn の戻り値 `{:done, body}` か `{:cont, state}` のみを見る。

  ## フィールド

  - `socket` - ソケット（任意。close は呼び出し側で行う場合などは未使用でもよい）
  - `phase` - 上位プロトコル用のフェーズ（ExTCP は参照しない。parse_fn 内で利用可）
  - `buffer` - 受信バイトの蓄積バッファ
  - `parse_fn` - (state) -> `{:done, body}` | `{:cont, state}`。buffer 追加済みの state を受け、解析して戻り値で継続/終了を返す。
  - `body` - 解析結果の格納用（parse_fn が `{:cont, state}` を返す間も state.body は FIN 時などに使われる）
  """
  defstruct socket: nil, phase: nil, buffer: <<>>, parse_fn: nil, body: nil
end
