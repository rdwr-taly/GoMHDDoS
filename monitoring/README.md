# GoMHDDoS Monitoring Setup

This directory contains the monitoring configuration for GoMHDDoS using Prometheus and Grafana.

## Available Metrics

The GoMHDDoS adapter exposes the following Prometheus metrics:

### Network Metrics
- `gomhddos_incoming_throughput_mbps` - Current incoming network throughput in Mbps
- `gomhddos_outgoing_throughput_mbps` - Current outgoing network throughput in Mbps  
- `gomhddos_bandwidth_limit_mbps` - Currently applied bandwidth limit in Mbps (live updates)

### Attack Metrics
- `gomhddos_threads_active` - Number of active attack threads
- `gomhddos_attack_duration_seconds` - Current attack duration in seconds
- `gomhddos_attack_running` - Attack running status (1=running, 0=stopped)

## Components

### Prometheus (`prometheus.yml`)
- Scrapes metrics from the GoMHDDoS container control API
- Two endpoints:
  - `/metrics` - System/container metrics (5s interval)
  - `/api/metrics` - Application metrics (10s interval)

### Grafana
- **Dashboard**: `dashboards/gomhddos-dashboard.json`
  - Real-time network throughput visualization
  - Bandwidth limit monitoring with live updates
  - Active thread count gauge
  - Attack duration tracking
  - Attack status overview

- **Data Source**: `datasources/prometheus.yml`
  - Connects Grafana to Prometheus
  - Configured to use `http://prometheus:9090`

## Quick Start

1. Start with monitoring:
   ```bash
   docker-compose --profile monitoring up
   ```

2. Access:
   - Grafana: http://localhost:3000 (admin/admin)
   - Prometheus: http://localhost:9090

## Key Features

- **Live Bandwidth Updates**: The dashboard shows the currently applied bandwidth limit, which updates in real-time when modified via the API
- **Network Traffic Visualization**: Separate incoming/outgoing throughput with bandwidth limit overlay
- **Attack Status Monitoring**: Real-time status of running attacks
- **Thread Activity Tracking**: Monitor the number of active attack threads

## Dashboard Panels

1. **Attack Status** - Current running status
2. **Network Throughput** - Real-time incoming/outgoing traffic with bandwidth limit line
3. **Active Threads** - Current thread count gauge
4. **Attack Duration** - Time since attack started
5. **Thread Activity Over Time** - Historical thread count
6. **Bandwidth Limit Over Time** - Historical bandwidth limit changes
