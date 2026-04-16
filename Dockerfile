# GoMHDDoS ShowRunner-managed Dockerfile
# Multi-stage build for optimized final image

FROM golang:1.23-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

COPY src/ ./

RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o gomhddos mhddos.go

# Stage 2: Runtime image
FROM python:3.11-slim AS runtime

ENV TZ=UTC \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    sudo \
    curl \
    tini \
    && curl -L https://github.com/codesenberg/bombardier/releases/latest/download/bombardier-linux-amd64 \
       -o /usr/local/bin/bombardier \
    && chmod +x /usr/local/bin/bombardier \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ARG APP_USER=appuser
RUN useradd -ms /bin/bash ${APP_USER} && \
    echo "${APP_USER} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    mkdir -p /app/binary /app/files/proxies /app/logs /config && \
    chown -R ${APP_USER}:${APP_USER} /app /config

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=builder /build/gomhddos /app/binary/gomhddos
COPY files/ ./files/
COPY main.py README.md ./

RUN chmod +x /app/binary/gomhddos && \
    chown -R ${APP_USER}:${APP_USER} /app /config

USER ${APP_USER}

EXPOSE 9090

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD curl -sf http://127.0.0.1:9090/healthz || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "python", "main.py"]

