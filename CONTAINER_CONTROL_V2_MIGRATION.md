# GoMHDDoS Container Control v2.0 Migration

## Overview
This document outlines the migration of GoMHDDoS from the old Container Control system to the new Container Control Core v2.0, which provides optional built-in services for process management, metrics collection, and traffic control.

## Key Changes

### 1. Simplified Adapter (`gomhddos_adapter/GoMHDDoSAdapter.py`)
- **Reduced from 319 lines to ~155 lines** (50% reduction)
- **Removed manual process management** - now handled by core services
- **Removed custom metrics collection** - now handled by core services  
- **Removed manual traffic control** - now handled by core services
- **Added v2.0 integration methods**:
  - `build_attack_command()` - for core process management
  - `on_before_core_traffic_control()` - to modify traffic control parameters
  - `on_core_process_exit()` - hook for process exit events

### 2. Enhanced Configuration (`config.yaml`)
- **Process Management Service**: Enabled with command factory
- **Metrics Service**: Automatic network and process monitoring
- **Traffic Control Service**: Built-in bandwidth limiting with tc
- **Privileged Commands**: System tuning for high-performance attacks

### 3. Updated Dockerfile
- **GitHub Integration**: Now clones Container Control Core from GitHub instead of copying local files
- **Cleaner build**: Removes the need to maintain local copies of core files
- **Consistent versioning**: Uses tagged release (v1.0.0) for stability

## Benefits

### For Developers
- **Less boilerplate**: No need to manage process lifecycle, metrics collection, or traffic control manually
- **Easier maintenance**: Core functionality is centralized and versioned
- **Better consistency**: All projects use the same core implementation

### For Operations
- **Automatic metrics**: Network throughput, process stats, and container metrics out-of-the-box
- **Built-in traffic control**: Bandwidth limiting without custom code
- **Better observability**: Prometheus metrics and health checks included

### For Security
- **Privilege separation**: Core handles privileged operations safely
- **System tuning**: Declarative privileged commands for performance optimization
- **User isolation**: Workload runs as non-root with proper sudo configuration

## Configuration Options

### Process Management
```yaml
process_management:
  enabled: true
  command_factory: "gomhddos_adapter.GoMHDDoSAdapter.build_attack_command"
```

### Traffic Control
```yaml
traffic_control:
  enabled: true
  interface: "eth0"
  bandwidth_mbps_key: "bandwidth_limit_mbps"
  default_bandwidth_mbps: 10
```

### Metrics Collection
```yaml
metrics:
  network_monitoring:
    enabled: true
    interface: "eth0"
  process_monitoring:
    enabled: true
```

## API Compatibility
The Container Control Core v2.0 maintains full API compatibility with the previous version:
- `POST /api/start` - Start attack with payload
- `POST /api/update` - Live configuration updates  
- `POST /api/stop` - Stop attack
- `GET /api/metrics` - JSON metrics
- `GET /metrics` - Prometheus metrics
- `GET /api/health` - Health check

## Next Steps
1. Test the updated GoMHDDoS container
2. Apply similar migrations to other projects:
   - traffic-generator-cli
   - flowrunner-cli  
   - GoCC-Attack (already partially done)
3. Verify all projects work with Container Control Core v2.0
