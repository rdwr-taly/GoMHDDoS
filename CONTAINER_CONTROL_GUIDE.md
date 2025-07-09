# GoMHDDoS Container Control Integration

## Overview

This integration combines the GoMHDDoS Layer 7 DDoS testing tool with the Container Control Core system, providing a complete containerized solution for controlled DDoS testing with real-time monitoring, live updates, and proper security isolation.

## Features

### 🔥 Core Integration Features
- **Real-time Attack Control**: Start, stop, and update attacks via REST API
- **Live Metrics**: Real-time throughput monitoring and performance statistics
- **Dual User Security**: Root for privileged network setup, appuser for attacks
- **Hot Configuration**: Live parameter updates during running attacks
- **Comprehensive Monitoring**: Built-in Prometheus metrics and Grafana dashboards

### 🚀 Enhanced Capabilities
- **Container Orchestration**: Full Docker and Docker Compose support
- **Health Monitoring**: Built-in health checks and status reporting
- **Resource Management**: Configurable CPU and memory limits
- **Network Control**: Advanced traffic shaping and bandwidth limiting
- **Graceful Shutdown**: Proper cleanup and signal handling

## Quick Start

### 1. Build and Run with Docker Compose

```bash
# Clone the repository
git clone <your-repo-url>
cd GoMHDDoS

# Build and start the container
docker-compose up -d

# Check status
docker-compose ps
curl http://localhost:8080/api/health
```

### 2. Start an Attack

```bash
# Basic GET flood attack
curl -X POST http://localhost:8080/api/start \
  -H "Content-Type: application/json" \
  -d '{
    "method": "GET",
    "url": "http://httpbin.org/delay/1",
    "threads": 50,
    "duration": 30
  }'
```

### 3. Monitor Attack Progress

```bash
# Get real-time metrics
curl http://localhost:8080/api/metrics

# Get Prometheus metrics
curl http://localhost:8080/metrics

# Check attack status
curl http://localhost:8080/api/health
```

### 4. Update Attack Parameters

```bash
# Increase thread count (requires restart)
curl -X POST http://localhost:8080/api/update \
  -H "Content-Type: application/json" \
  -d '{
    "threads": 100,
    "debug": true
  }'
```

### 5. Stop Attack

```bash
# Graceful stop
curl -X POST http://localhost:8080/api/stop \
  -H "Content-Type: application/json" \
  -d '{}'
```

## API Reference

### Attack Management

#### `POST /api/start`
Start a new GoMHDDoS attack.

**Request Body:**
```json
{
  "method": "GET",              // Required: Attack method (GET, POST, CFB, SLOW, etc.)
  "url": "http://target.com",   // Required: Target URL
  "threads": 100,               // Optional: Number of threads (default: 100)
  "duration": 60,               // Optional: Attack duration in seconds (default: 60)
  "proxyfile": "files/proxies/http.txt",  // Optional: Proxy file path
  "rpc": 50,                    // Optional: Requests per connection (default: 50)
  "cookie": "session=abc123",   // Optional: Cookie string
  "debug": false,               // Optional: Enable debug mode (default: false)
  "bandwidth_limit_mbps": 100   // Optional: Bandwidth limit for privileged setup
}
```

**Response:**
```json
{
  "message": "start initiated"
}
```

#### `POST /api/update`
Update attack parameters during execution.

**Request Body:**
```json
{
  "threads": 200,     // Update thread count (requires restart)
  "debug": true,      // Toggle debug mode
  "duration": 120     // Update duration
}
```

**Response:**
```json
{
  "message": "update applied"
}
```

#### `POST /api/stop`
Stop the current attack.

**Request Body:**
```json
{
  "force": false  // Optional: Force immediate termination
}
```

**Response:**
```json
{
  "message": "stop initiated"
}
```

### Monitoring

#### `GET /api/health`
Get service health status.

**Response:**
```json
{
  "status": "healthy",
  "app_status": "running"
}
```

#### `GET /api/metrics`
Get comprehensive JSON metrics.

**Response:**
```json
{
  "timestamp": "2025-01-09T12:00:00.000Z",
  "app_status": "running",
  "container_status": "running",
  "network": {
    "bytes_sent": 1048576,
    "bytes_recv": 512000,
    "packets_sent": 1024,
    "packets_recv": 512
  },
  "system": {
    "cpu_percent": 45.2,
    "memory_percent": 32.1,
    "memory_available_mb": 1024.5,
    "memory_used_mb": 512.3
  },
  "metrics": {
    "incoming_throughput_mbps": 12.5,
    "outgoing_throughput_mbps": 25.3,
    "threads_active": 100,
    "attack_duration_seconds": 60,
    "bandwidth_limit_mbps": 50,
    "target_url": "http://target.com",
    "attack_method": "GET",
    "duration_configured_seconds": 300,
    "current_config": {
      "method": "GET",
      "url": "http://target.com",
      "threads": 100,
      "duration": 60
    }
  }
}
```

#### `GET /metrics`
Get Prometheus-formatted metrics.

**Response:**
```
# HELP container_cpu_percent CPU usage %
container_cpu_percent 45.2
# HELP gomhddos_incoming_throughput_mbps Current incoming throughput in Mbps
gomhddos_incoming_throughput_mbps 12.5
# HELP gomhddos_outgoing_throughput_mbps Current outgoing throughput in Mbps
gomhddos_outgoing_throughput_mbps 25.3
# HELP gomhddos_threads_active Number of active attack threads
gomhddos_threads_active 100
# HELP gomhddos_attack_duration_seconds Current attack duration
gomhddos_attack_duration_seconds 60
# HELP gomhddos_bandwidth_limit_mbps Currently applied bandwidth limit in Mbps
gomhddos_bandwidth_limit_mbps 50
# HELP gomhddos_attack_running Attack running status (1=running, 0=stopped)
gomhddos_attack_running 1
...
```

## Configuration

### Environment Variables

- `LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `CCC_CONFIG_FILE`: Path to config.yaml file
- `TZ`: Timezone (default: UTC)

### config.yaml

```yaml
adapter:
  class: gomhddos_adapter.GoMHDDoSAdapter
  primary_payload_key: method
  run_as_user: appuser
```

## Advanced Features

### Traffic Control Integration

The adapter supports advanced network configuration through privileged hooks:

```json
{
  "method": "GET",
  "url": "http://target.com",
  "threads": 100,
  "bandwidth_limit_mbps": 50  // Automatically sets up traffic control
}
```

### Proxy Management

Support for HTTP, SOCKS4, and SOCKS5 proxies:

```bash
# Create custom proxy file
echo "proxy1.example.com:8080" > files/proxies/custom.txt
echo "user:pass@proxy2.example.com:3128" >> files/proxies/custom.txt

# Use custom proxy file
curl -X POST http://localhost:8080/api/start \
  -H "Content-Type: application/json" \
  -d '{
    "method": "POST",
    "url": "http://target.com",
    "proxyfile": "files/proxies/custom.txt"
  }'
```

### High-Performance Attacks

For high-concurrency attacks, the system automatically:
- Increases file descriptor limits
- Optimizes network buffers
- Manages system resources

```json
{
  "method": "STRESS",
  "url": "http://target.com",
  "threads": 5000,  // Automatically triggers high-performance optimizations
  "duration": 300
}
```

## Monitoring and Observability

### Built-in Dashboards

Start with monitoring stack:
```bash
docker-compose --profile monitoring up -d
```

- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090

### Key Metrics to Monitor

1. **Attack Performance**:
   - `gomhddos_incoming_throughput_mbps`: Current incoming throughput 
   - `gomhddos_outgoing_throughput_mbps`: Current outgoing throughput
   - `gomhddos_bandwidth_limit_mbps`: Applied bandwidth limit
   - `gomhddos_attack_duration_seconds`: Attack runtime
   - `gomhddos_threads_active`: Active attack threads

2. **System Health**:
   - `container_cpu_percent`: CPU usage
   - `container_memory_percent`: Memory usage
   - `gomhddos_attack_running`: Attack running status

3. **Network Metrics**:
   - `container_network_bytes_sent_total`: Total bytes sent
   - `container_network_packets_sent`: Total packets sent

## Security Considerations

### Privilege Separation

The system uses two users:
- **root**: For privileged network setup (traffic control, firewall rules)
- **appuser**: For running attacks (isolated, non-privileged)

### Resource Limits

Configure appropriate limits in docker-compose.yml:
```yaml
deploy:
  resources:
    limits:
      memory: 2G
      cpus: '2.0'
```

### Network Isolation

Use dedicated networks for testing:
```yaml
networks:
  gomhddos-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

## Troubleshooting

### Common Issues

1. **Binary not found**:
   ```bash
   # Check if binary exists
   docker exec gomhddos-container-control ls -la /app/binary/
   
   # Rebuild if needed
   docker-compose build --no-cache
   ```

2. **Permission denied**:
   ```bash
   # Check user permissions
   docker exec gomhddos-container-control id appuser
   
   # Fix permissions
   docker exec -u root gomhddos-container-control chown -R appuser:appuser /app
   ```

3. **High memory usage**:
   ```bash
   # Monitor memory usage
   curl http://localhost:8080/api/metrics | jq '.system.memory_percent'
   
   # Reduce thread count
   curl -X POST http://localhost:8080/api/update -d '{"threads": 50}'
   ```

### Debugging

Enable debug mode:
```json
{
  "method": "GET",
  "url": "http://target.com",
  "debug": true
}
```

Check logs:
```bash
docker-compose logs -f gomhddos-control
```

## Performance Tuning

### Container Optimization

1. **CPU Scaling**:
   ```yaml
   deploy:
     resources:
       limits:
         cpus: '4.0'  # Scale based on thread count
   ```

2. **Memory Allocation**:
   ```yaml
   deploy:
     resources:
       limits:
         memory: 4G  # ~1GB per 1000 threads
   ```

3. **Network Buffers**:
   ```yaml
   sysctls:
     - net.core.rmem_max=26214400
     - net.core.wmem_max=26214400
   ```

### Attack Optimization

1. **Thread Scaling**: Start with 100 threads, scale based on target capacity
2. **Connection Reuse**: Use higher RPC values (100-200) for persistent connections
3. **Proxy Rotation**: Use multiple proxy files for better distribution

## Integration Examples

### CI/CD Pipeline

```yaml
# .github/workflows/load-test.yml
- name: Run Load Test
  run: |
    docker-compose up -d
    
    # Start attack
    curl -X POST http://localhost:8080/api/start \
      -d '{"method": "GET", "url": "${{ env.TEST_URL }}", "threads": 50, "duration": 30}'
    
    # Monitor for 30 seconds
    sleep 30
    
    # Get results
    curl http://localhost:8080/api/metrics > test-results.json
    
    # Stop attack
    curl -X POST http://localhost:8080/api/stop -d '{}'
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: gomhddos-control
spec:
  replicas: 1
  selector:
    matchLabels:
      app: gomhddos-control
  template:
    metadata:
      labels:
        app: gomhddos-control
    spec:
      containers:
      - name: gomhddos
        image: your-registry/gomhddos-control:latest
        ports:
        - containerPort: 8080
        resources:
          limits:
            memory: "2Gi"
            cpu: "2000m"
          requests:
            memory: "512Mi"
            cpu: "500m"
        securityContext:
          capabilities:
            add:
            - NET_ADMIN
```

## Legal and Ethical Use

⚠️ **IMPORTANT**: This tool is for authorized testing only.

- ✅ **Authorized Use**: Testing your own systems, penetration testing with written permission
- ❌ **Unauthorized Use**: Attacking systems without permission is illegal

Always ensure:
1. Written authorization before testing
2. Proper documentation of testing activities  
3. Compliance with local laws and regulations
4. Responsible disclosure of findings

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

Areas for contribution:
- Enhanced metrics parsing from GoMHDDoS output
- Additional attack method support
- Performance optimizations
- Documentation improvements

## License

This project is for educational and authorized testing purposes only. Users are responsible for compliance with all applicable laws and regulations.
