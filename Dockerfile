# 前端构建阶段：产物复制进运行镜像，由 opti api 同源提供
FROM node:24-slim AS web
RUN npm install -g pnpm@11.9.0
WORKDIR /web
COPY web/package.json web/pnpm-lock.yaml web/pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm run build

FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
# S3-C public-repository scanning: install git and checksum-verified gitleaks.
ARG GITLEAKS_VERSION=8.21.2
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends git ca-certificates curl; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) ga=x64 ;; arm64) ga=arm64 ;; *) echo "unsupported arch $arch"; exit 1 ;; esac; \
    cd /tmp; \
    base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"; \
    curl -fsSLO "${base}/gitleaks_${GITLEAKS_VERSION}_linux_${ga}.tar.gz"; \
    curl -fsSLO "${base}/gitleaks_${GITLEAKS_VERSION}_checksums.txt"; \
    grep " gitleaks_${GITLEAKS_VERSION}_linux_${ga}.tar.gz\$" "gitleaks_${GITLEAKS_VERSION}_checksums.txt" | sha256sum -c -; \
    tar -xzf "gitleaks_${GITLEAKS_VERSION}_linux_${ga}.tar.gz" -C /usr/local/bin gitleaks; \
    rm -f /tmp/gitleaks_*; \
    apt-get purge -y curl; apt-get autoremove -y; rm -rf /var/lib/apt/lists/*
WORKDIR /app
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy PYTHONUNBUFFERED=1
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY config ./config
COPY eval ./eval
RUN uv sync --frozen --no-dev
COPY --from=web /web/dist ./web/dist
ENV PATH="/app/.venv/bin:$PATH" OPTI_WEB_DIST=/app/web/dist
# 非 root 运行（设计文档 19 安全要求）
RUN useradd --system --uid 10001 opti && mkdir -p /app/data /run/opti-control && chown opti /app/data /run/opti-control
USER opti
CMD ["opti", "connectors"]
