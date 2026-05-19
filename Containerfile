


FROM ghcr.io/astral-sh/uv:latest AS uv
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    p7zip-full \
    binutils \
    python3 \
    file \
    xxd \
    ripgrep \
    jq \
    && rm -rf /var/lib/apt/lists/*

COPY --from=uv /uv /usr/local/bin/uv

ENV UV_BREAK_SYSTEM_PACKAGES=1
RUN uv pip install --system \
    macholib \
    trufflehog

# Non-root analyst user
RUN useradd -m -u 1000 analyst
USER analyst

ENV PYTHONPATH=/work/src

WORKDIR /work
COPY --chown=analyst:analyst scripts/ ./scripts/
COPY --chown=analyst:analyst src/ ./src/

ENTRYPOINT ["bash", "scripts/run_all.sh"]
