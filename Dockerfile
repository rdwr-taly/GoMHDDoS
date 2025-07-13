# GoMHDDoS Container Control Integration Dockerfile
# Multi-stage build for optimized final image

# Stage 1: Build Go binary
FROM golang:1.23-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Set working directory
WORKDIR /build

# Copy Go source files
COPY src/ ./

# Build the GoMHDDoS binary
RUN go mod tidy && \
    CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s" \
    -o gomhddos mhddos.go

# Stage 2: Runtime image
FROM python:3.11-slim

# Set environment variables
ENV TZ=UTC \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Network tools for advanced features
    iproute2 \
    iptables \
    sudo \
    curl \
    # Process management
    tini \
    # Optional: bombardier for BOMB method
    && curl -L https://github.com/codesenberg/bombardier/releases/latest/download/bombardier-linux-amd64 \
       -o /usr/local/bin/bombardier \
    && chmod +x /usr/local/bin/bombardier \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create application user
ARG APP_USER=appuser
RUN useradd -ms /bin/bash ${APP_USER} && \
    echo "${APP_USER} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers && \
    # Create necessary directories
    mkdir -p /app/binary /app/files/proxies /app/logs && \
    chown -R ${APP_USER}:${APP_USER} /app

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Clone Container Control Core v2.0 from GitHub
RUN apt-get update && apt-get install -y --no-install-recommends git && \
    git clone --branch v1.0.0 --depth 1 https://github.com/rdwr-taly/container-control.git /tmp/container-control && \
    cp /tmp/container-control/container_control_core.py . && \
    cp /tmp/container-control/app_adapter.py . && \
    rm -rf /tmp/container-control && \
    apt-get remove -y git && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

# Copy application-specific files
COPY gomhddos_adapter.py .
COPY config.yaml .

# Copy GoMHDDoS binary from builder stage
COPY --from=builder /build/gomhddos /app/binary/gomhddos

# Copy GoMHDDoS files and data
COPY files/ ./files/
COPY README.md .

# Set permissions
RUN chmod +x /app/binary/gomhddos && \
    chown -R ${APP_USER}:${APP_USER} /app

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Ensure proper permissions\n\
chown -R appuser:appuser /app\n\
chmod +x /app/binary/gomhddos\n\
\n\
# Start the container control service\n\
exec python -m uvicorn container_control_core:app --host 0.0.0.0 --port 8080\n\
' > /app/entrypoint.sh && \
    chmod +x /app/entrypoint.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/api/health || exit 1

# Expose port
EXPOSE 8080

# Use tini as init system
ENTRYPOINT ["/usr/bin/tini", "--"]

# Start the application
CMD ["/app/entrypoint.sh"]
