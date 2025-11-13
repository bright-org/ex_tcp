FROM ghcr.io/livebook-dev/livebook:latest AS base

RUN apt-get update && \
    apt-get install -y python3 && \
    rm -rf /var/lib/apt/lists/*

USER livebook