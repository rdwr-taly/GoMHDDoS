"""
GoMHDDoS Container Control Adapter (v3.0 - Container Control Core v2.0)

This adapter integrates the GoMHDDoS Layer 7 DDoS testing tool with the
Container Control Core v2.0 system. Leverages new core services for process
management, metrics collection, and traffic control.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List

from app_adapter import ApplicationAdapter


class GoMHDDoSAdapter(ApplicationAdapter):
    """
    Container Control adapter for GoMHDDoS.
    Simplified for v2.0 core services - the core handles process management,
    metrics collection, and traffic control automatically.
    """

    def __init__(self, static_cfg: Dict[str, Any] | None = None) -> None:
        super().__init__(static_cfg)
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
        """
        Start a GoMHDDoS attack with the specified parameters.
        
        With Container Control Core v2.0, this method just validates the payload
        and stores config. The core handles the actual process management via
        build_attack_command().
        """
        if 'method' not in start_payload or 'url' not in start_payload:
            raise ValueError("Attack 'method' and 'url' are required")

        # Store the configuration for command building
        self.current_config = start_payload.copy()
        
        # Return success - the core will call build_attack_command() to get the command
        return "gomhddos_configured"

    def stop(self) -> None:
        """
        Stop the GoMHDDoS attack.
        
        With Container Control Core v2.0, the core handles process termination.
        This method is called for any adapter-specific cleanup.
        """
        self.current_config = {}

    def update(self, update_payload: Dict[str, Any]) -> bool:
        """
        Apply live configuration updates.
        
        Most updates will trigger a restart via the core's process management.
        """
        if not self.current_config:
            return False

        # Update the stored configuration
        self.current_config.update(update_payload)
        return True

    def get_metrics(self) -> Dict[str, Any]:
        """
        Return current attack metrics.
        
        The core v2.0 automatically collects network and process metrics.
        This method provides attack-specific metrics.
        """
        metrics = {}
        
        # Add configuration info to metrics
        if self.current_config:
            metrics.update({
                'target_url': self.current_config.get('url'),
                'attack_method': self.current_config.get('method'),
                'threads_configured': self.current_config.get('threads', 100),
                'duration_configured_seconds': self.current_config.get('duration', 60),
                'rpc_configured': self.current_config.get('rpc', 50),
                'bandwidth_limit_mbps': self.current_config.get('bandwidth_limit_mbps', 10),
            })
            
            if 'proxyfile' in self.current_config:
                metrics['proxy_file'] = self.current_config['proxyfile']
            if 'cookie' in self.current_config:
                metrics['cookie_configured'] = bool(self.current_config['cookie'])
            if 'debug' in self.current_config:
                metrics['debug_mode'] = self.current_config['debug']

        return metrics

    def prometheus_metrics(self) -> List[str]:
        """Return Prometheus-formatted metrics."""
        metrics = []
        
        if self.current_config:
            threads = self.current_config.get('threads', 100)
            bandwidth = self.current_config.get('bandwidth_limit_mbps', 10)
            
            metrics.extend([
                "# HELP gomhddos_threads_configured Number of configured attack threads",
                f"gomhddos_threads_configured {threads}",
                "# HELP gomhddos_bandwidth_limit_mbps Configured bandwidth limit in Mbps",
                f"gomhddos_bandwidth_limit_mbps {bandwidth}",
            ])

        return metrics

    # ---------- NEW v2.0 Core Service Integration Methods ------------------ #

    def build_attack_command(self, payload: Dict[str, Any]) -> List[str]:
        """
        Build the GoMHDDoS command for the core's process management service.
        
        This method is called by the core when process_management.command_factory
        is configured in config.yaml.
        """
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

    def on_before_core_traffic_control(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Hook called before the core applies traffic control.
        Can modify the payload to adjust traffic control parameters.
        """
        # Ensure we have a sensible default bandwidth if not specified
        if 'bandwidth_limit_mbps' not in payload:
            payload['bandwidth_limit_mbps'] = 10
            
        return payload

    def on_core_process_exit(self, return_code: int, stdout: str, stderr: str) -> None:
        """
        Hook called when the core-managed GoMHDDoS process exits.
        """
        if return_code != 0:
            print(f"GoMHDDoS process exited with code {return_code}")
            if stderr:
                print(f"stderr: {stderr}")
        
        # Clear configuration on exit
        self.current_config = {}


# --------------------------------------------------------------------------- #
# Module-level helpers

def build_attack_command(payload: Dict[str, Any]) -> List[str]:
    """Compatibility wrapper for Container Control Core.

    The core expects ``process_management.command_factory`` to resolve to a
    module attribute.  Earlier versions exposed ``build_attack_command`` only as
    an instance method on :class:`GoMHDDoSAdapter`, which caused an
    ``AttributeError`` when the core tried to load it directly from the module.

    This wrapper mirrors the adapter's method so the core can import and invoke
    it without an adapter instance.
    """

    adapter = GoMHDDoSAdapter()
    return adapter.build_attack_command(payload)
