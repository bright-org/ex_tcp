#!/bin/sh
set -eu

# すでに存在していた場合は消しておく（コンテナ再起動時のエラー防止）
if ip link show tap0 >/dev/null 2>&1; then
  ip link del tap0
fi

if ip link show tap1 >/dev/null 2>&1; then
  ip link del tap1
fi

if ip link show br0 >/dev/null 2>&1; then
  ip link del br0
fi

# TAP デバイス作成（IPは振らない）
ip tuntap add tap0 mode tap
ip tuntap add tap1 mode tap

# ブリッジ作成
ip link add br0 type bridge

# TAP をブリッジにぶら下げる
ip link set tap0 master br0
ip link set tap1 master br0

# 有効化（UP）
ip link set dev tap0 up
ip link set dev tap1 up
ip link set dev br0 up

# 確認用（ログが邪魔なら削除して構いません）
ip link show tap0
ip link show tap1
ip link show br0
