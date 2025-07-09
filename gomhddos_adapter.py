"""
GoMHDDoS Container Control Adapter (v2.2 - Live Bandwidth Metric)

This adapter integrates the GoMHDDoS Layer 7 DDoS testing tool with the
Container Control Core system. It features robust psutil-based metrics and
reports the currently active bandwidth limit, which can be updated live.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

import psutil

from app_adapter import ApplicationAdapter


class GoMHDDoSAdapter(ApplicationAdapter):
    """
    Container Control adapter for GoMHDDoS.
    Manages attack lifecycle, psutil-based metrics, and live updates.
    """
    # Define a default bandwidth limit if none is specified.
    DEFAULT_BANDWIDTH_MBPS = 10

    def __init__(self, static_cfg: Dict[str, Any] | None = None) -> None:
        super().__init__(static_cfg)

        # Process management
        self.process: Optional[subprocess.Popen] = None
        self.process_lock = threading.Lock()
        self.start_time: Optional[float] = None

        # Metrics tracking
        self.metrics_thread: Optional[threading.Thread] = None
        self.metrics_stop_event = threading.Event()
        self.current_metrics = {
            'incoming_throughput_mbps': 0,
            'outgoing_throughput_mbps': 0,
            'threads_active': 0,
            'attack_duration_seconds': 0,
            'bandwidth_limit_mbps': 0,  # Live value of the applied limit
            'status': 'stopped'
        }
        # State for psutil throughput calculation
        self._prev_net_io: Optional[psutil._common.snetio] = None
        self._prev_time: Optional[float] = None

        # Configuration
        self.current_config: Dict[str, Any] = {}
        self.binary_path = '/app/binary/gomhddos'

        self._ensure_binary()

    def _ensure_binary(self) -> None:
        """Ensure the GoMHDDoS binary exists and is executable."""
        binary_paths = ['/app/binary/gomhddos', '/app/gomhddos']
        for path in binary_paths:
            if os.path.exists(path):
                self.binary_path = path
                os.chmod(path, 0o755)
                return
        raise RuntimeError("GoMHDDoS binary not found at expected paths.")

    def start(self, start_payload: Dict[str, Any], *, ensure_user) -> Any:
        """Starts a GoMHDDoS attack with the specified parameters."""
        # Store ensure_user function for later use in updates
        self._ensure_user_func = ensure_user
        
        with self.process_lock:
            if self.process and self.process.poll() is None:
                self.stop()

            if 'method' not in start_payload or 'url' not in start_payload:
                raise ValueError("Attack 'method' and 'url' are required")

            # Store the configuration, applying the default bandwidth if not set
            self.current_config = start_payload.copy()
            effective_bandwidth = self.current_config.get(
                'bandwidth_limit_mbps', self.DEFAULT_BANDWIDTH_MBPS
            )
            self.current_config['bandwidth_limit_mbps'] = effective_bandwidth

            cmd = self._build_attack_command(self.current_config)

            try:
                self.process = subprocess.Popen(
                    ensure_user(cmd),
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    cwd='/app'
                )

                self.start_time = time.time()
                self._start_metrics_collection()

                # Update live metrics state
                self.current_metrics.update({
                    'status': 'running',
                    'threads_active': self.current_config.get('threads', 100),
                    'bandwidth_limit_mbps': effective_bandwidth
                })
                return self.process

            except Exception as e:
                self.current_metrics['status'] = 'error'
                raise RuntimeError(f"Failed to start GoMHDDoS attack: {e}")

    def stop(self) -> None:
        """Stops the current GoMHDDoS attack gracefully."""
        with self.process_lock:
            if self.process and self.process.poll() is None:
                try:
                    self.process.terminate()
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
                except Exception:
                    pass
                self.process = None

            self._stop_metrics_collection()
            # Reset metrics to a stopped state
            self.current_metrics['status'] = 'stopped'
            self.current_metrics['threads_active'] = 0
            self.current_metrics['bandwidth_limit_mbps'] = 0
            self.start_time = None

    def update(self, update_payload: Dict[str, Any]) -> bool:
        """
        Apply live configuration updates.
        Updates to 'threads' or 'bandwidth_limit_mbps' require a restart.
        """
        if not self.process or self.process.poll() is not None:
            return False

        needs_restart = False
        restart_params = ['threads', 'bandwidth_limit_mbps']
        for param in restart_params:
            # Check if the param is in the update and its value is different
            if param in update_payload and update_payload[param] != self.current_config.get(param):
                needs_restart = True
                break

        if needs_restart:
            try:
                new_config = self.current_config.copy()
                new_config.update(update_payload)

                # Use the ensure_user function passed to us originally
                # Store it during start() to avoid circular imports
                if hasattr(self, '_ensure_user_func'):
                    ensure_user = self._ensure_user_func
                else:
                    # Fallback to a basic implementation
                    def ensure_user(cmd): return cmd

                self.stop()
                time.sleep(1)
                self.start(new_config, ensure_user=ensure_user)
                return True
            except Exception:
                return False

        updated = False
        if 'debug' in update_payload:
            self.current_config['debug'] = update_payload['debug']
            updated = True

        return updated

    def get_metrics(self) -> Dict[str, Any]:
        """Return current attack metrics, with config flattened."""
        metrics = self.current_metrics.copy()

        # Flatten the current configuration into the metrics dictionary
        config = self.current_config.copy()
        metrics['target_url'] = config.get('url')
        metrics['attack_method'] = config.get('method')
        metrics['duration_configured_seconds'] = config.get('duration')

        # Remove redundant status field already at the root level
        metrics.pop('status', None)

        return metrics

    def prometheus_metrics(self) -> List[str]:
        """Return Prometheus-formatted metrics."""
        metrics = [
            "# HELP gomhddos_incoming_throughput_mbps Current incoming throughput in Mbps.",
            f"gomhddos_incoming_throughput_mbps {self.current_metrics.get('incoming_throughput_mbps', 0)}",
            "# HELP gomhddos_outgoing_throughput_mbps Current outgoing throughput in Mbps.",
            f"gomhddos_outgoing_throughput_mbps {self.current_metrics.get('outgoing_throughput_mbps', 0)}",
            "# HELP gomhddos_threads_active Number of active attack threads",
            f"gomhddos_threads_active {self.current_metrics.get('threads_active', 0)}",
            "# HELP gomhddos_attack_duration_seconds Current attack duration",
            f"gomhddos_attack_duration_seconds {self.current_metrics.get('attack_duration_seconds', 0)}",
            "# HELP gomhddos_bandwidth_limit_mbps Currently applied bandwidth limit in Mbps.",
            f"gomhddos_bandwidth_limit_mbps {self.current_metrics.get('bandwidth_limit_mbps', 0)}",
        ]

        status_value = 1 if self.current_metrics.get('status') == 'running' else 0
        metrics.extend([
            "# HELP gomhddos_attack_running Attack running status (1=running, 0=stopped)",
            f"gomhddos_attack_running {status_value}",
        ])
        return metrics

    def pre_start_hooks(self, start_payload: Dict[str, Any]) -> None:
        """Privileged setup hooks for traffic control."""
        self.post_stop_hooks()

        bandwidth = start_payload.get('bandwidth_limit_mbps', self.DEFAULT_BANDWIDTH_MBPS)
        if bandwidth and bandwidth > 0:
            try:
                subprocess.run([
                    'tc', 'qdisc', 'add', 'dev', 'eth0', 'root',
                    'tbf', 'rate', f'{bandwidth}mbit',
                    'burst', f'{int(bandwidth * 1000 / 8)}k' # Burst buffer of ~1 sec
                ], check=True, stderr=subprocess.PIPE)
            except Exception:
                pass # Non-critical failure

    def post_stop_hooks(self) -> None:
        """Cleanup hooks to remove traffic control rules."""
        try:
            subprocess.run(
                ['tc', 'qdisc', 'del', 'dev', 'eth0', 'root'],
                check=False, stderr=subprocess.PIPE
            )
        except Exception:
            pass

    def _build_attack_command(self, payload: Dict[str, Any]) -> List[str]:
        """Build the GoMHDDoS command from the payload."""
        cmd = [self.binary_path]
        cmd.extend(['-method', payload['method']])
        cmd.extend(['-url', payload['url']])
        cmd.extend(['-threads', str(payload.get('threads', 100))])
        cmd.extend(['-duration', str(payload.get('duration', 60))])
        cmd.extend(['-rpc', str(payload.get('rpc', 50))])
        if 'proxyfile' in payload:
            cmd.extend(['-proxyfile', payload['proxyfile']])
        if payload.get('cookie'):
            cmd.extend(['-cookie', payload['cookie']])
        if payload.get('debug'):
            cmd.append('-debug')
        return cmd

    def _start_metrics_collection(self) -> None:
        """Start the metrics collection thread using psutil."""
        self._prev_net_io = psutil.net_io_counters()
        self._prev_time = time.time()
        self.metrics_stop_event.clear()
        self.metrics_thread = threading.Thread(
            target=self._collect_metrics,
            daemon=True
        )
        self.metrics_thread.start()

    def _stop_metrics_collection(self) -> None:
        """Stop the metrics collection thread."""
        if self.metrics_thread:
            self.metrics_stop_event.set()
            self.metrics_thread.join(timeout=2)
            self.metrics_thread = None

    def _collect_metrics(self) -> None:
        """Periodically calculates throughput using psutil and updates metrics."""
        while not self.metrics_stop_event.is_set():
            if not self.process or self.process.poll() is not None:
                self.current_metrics['status'] = 'stopped'
                self.current_metrics['threads_active'] = 0
                self.current_metrics['bandwidth_limit_mbps'] = 0
                break

            incoming_mbps, outgoing_mbps = self._calculate_throughput()
            if incoming_mbps is not None:
                self.current_metrics['incoming_throughput_mbps'] = incoming_mbps
                self.current_metrics['outgoing_throughput_mbps'] = outgoing_mbps

            if self.start_time:
                self.current_metrics['attack_duration_seconds'] = int(time.time() - self.start_time)

            time.sleep(1)

    def _calculate_throughput(self) -> tuple[Optional[float], Optional[float]]:
        """Calculates incoming and outgoing throughput in Mbps using psutil."""
        try:
            current_net_io = psutil.net_io_counters()
            current_time = time.time()

            if self._prev_net_io is None or self._prev_time is None:
                self._prev_net_io = current_net_io
                self._prev_time = current_time
                return None, None

            elapsed_time = current_time - self._prev_time
            if elapsed_time < 0.1:
                return None, None

            bytes_sent_diff = current_net_io.bytes_sent - self._prev_net_io.bytes_sent
            bytes_recv_diff = current_net_io.bytes_recv - self._prev_net_io.bytes_recv

            outgoing_mbps = (bytes_sent_diff * 8) / (elapsed_time * 1_000_000)
            incoming_mbps = (bytes_recv_diff * 8) / (elapsed_time * 1_000_000)

            self._prev_net_io = current_net_io
            self._prev_time = current_time

            return round(incoming_mbps, 2), round(outgoing_mbps, 2)
        except Exception:
            return None, None