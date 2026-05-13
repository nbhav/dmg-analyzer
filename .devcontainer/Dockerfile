FROM ghcr.io/astral-sh/uv:latest AS uv
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    p7zip-full \
    binutils \
    file \
    xxd \
    ripgrep \
    jq \
    shellcheck \
    git \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /usr/local/bin/uv

ENV UV_BREAK_SYSTEM_PACKAGES=1
RUN uv pip install --system --no-cache \
    macholib \
    black \ 
    isort \
    ruff \
    mypy

RUN useradd -m -s /bin/bash vscode \
    && echo "vscode ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
