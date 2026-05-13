# Dev Container Dockerfile for DMG Analyzer Development
# This creates the VS Code development environment with all necessary tools
# for developing and testing the DMG analysis pipeline.

FROM ghcr.io/astral-sh/uv:latest AS uv
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Ubuntu system packages:
# - python3: Python interpreter for development and running the application
# - file: File type identification utility
# - ripgrep: Fast text search tool (alternative to grep)
# - jq: JSON processor for working with JSON data
# - shellcheck: Shell script linter (VS Code extension uses this)
# - git: Version control system
# - curl: HTTP client for downloading files and API calls
# - sudo: Allow vscode user to run commands as root when needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    file \
    ripgrep \
    jq \
    shellcheck \
    git \
    curl \
    sudo \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /usr/local/bin/uv

# Allow uv to install packages system-wide (required for development environment)
ENV UV_BREAK_SYSTEM_PACKAGES=1

# Python development tools and linters:
# - black: Python code formatter (VS Code extension uses this)
# - isort: Python import sorter (VS Code extension uses this)
# - ruff: Fast Python linter and formatter (VS Code extension uses this)
# - mypy: Python static type checker (VS Code extension uses this)
RUN uv pip install --system --no-cache \
    black \
    isort \
    ruff \
    mypy

# Create vscode user with sudo privileges for development
RUN useradd -m -s /bin/bash vscode \
    && echo "vscode ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers
