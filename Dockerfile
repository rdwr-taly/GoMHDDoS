# GoMHDDoS ShowRunner-managed Dockerfile
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
    git \
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
    mkdir -p /app/binary /app/files/proxies /app/logs /config && \
    chown -R ${APP_USER}:${APP_USER} /app /config

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy GoMHDDoS binary from builder stage
COPY --from=builder /build/gomhddos /app/binary/gomhddos

# Copy application entry point
COPY main.py .

# Copy GoMHDDoS files and data
COPY files/ ./files/
COPY README.md .

# Set permissions
RUN chmod +x /app/binary/gomhddos && \
    chown -R ${APP_USER}:${APP_USER} /app

# Health check against ShowRunner SDK metrics/health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:9090/healthz || exit 1

# Expose metrics/health port
EXPOSE 9090

# Switch to non-root user
USER ${APP_USER}

# Use tini as init system
ENTRYPOINT ["/usr/bin/tini", "--"]

# Start the application
CMD ["python", "main.py"]
