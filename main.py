"""ShowRunner-managed entry point for GoMHDDoS."""

import subprocess
import signal
import logging
import os
import threading

from showrunner_sdk import config, metrics, health

logger = logging.getLogger("gomhddos")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)

BINARY_PATH = "/app/binary/gomhddos"

# ── App-specific Prometheus metrics ──
threads_gauge = metrics.gauge("attack_threads", "Configured attack threads")
duration_gauge = metrics.gauge("attack_duration_seconds", "Configured attack duration")
rpc_gauge = metrics.gauge("attack_rpc", "Configured requests per connection")
status_gauge = metrics.gauge("attack_status", "Attack status (1=running, 0=stopped)")
runs_total = metrics.counter("attack_runs_total", "Total number of attack runs started")
metrics.set_app_info(name="gomhddos", version="2.0.0")


# ── Process management ──
process: subprocess.Popen | None = None
process_lock = threading.Lock()


def build_command(cfg_data: dict) -> list[str]:
    """Build gomhddos CLI command from config dict.

    Expected config keys (mirrors the Go binary's flag interface):
        method   - Attack method, e.g. GET, POST, CFB, SLOW (required)
        url      - Target URL (required)
        threads  - Concurrent threads (default 100)
        duration - Attack duration in seconds (default 60)
        rpc      - Requests per connection (default 50)
        proxyfile - Path to proxy list file (optional)
        cookie   - Cookie string (optional)
        debug    - Enable debug logging (optional, bool)
        bombardier - Path to bombardier binary (optional)
    """
    cmd = [BINARY_PATH]
    cmd.extend(["-method", cfg_data["method"]])
    cmd.extend(["-url", cfg_data["url"]])
    cmd.extend(["-threads", str(cfg_data.get("threads", 100))])
    cmd.extend(["-duration", str(cfg_data.get("duration", 60))])
    cmd.extend(["-rpc", str(cfg_data.get("rpc", 50))])

    if "proxyfile" in cfg_data:
        cmd.extend(["-proxyfile", cfg_data["proxyfile"]])
    if cfg_data.get("cookie"):
        cmd.extend(["-cookie", cfg_data["cookie"]])
    if cfg_data.get("debug"):
        cmd.append("-debug")
    if cfg_data.get("bombardier"):
        cmd.extend(["-bombardier", cfg_data["bombardier"]])

    return cmd


def start_attack(cfg_data: dict) -> None:
    """Validate config, build command, and launch the Go binary."""
    global process

    if not cfg_data.get("method") or not cfg_data.get("url"):
        logger.warning("Config missing required 'method' or 'url' -- skipping start")
        health.set_status("error", reason="missing method or url in config")
        return

    with process_lock:
        stop_attack()

        cmd = build_command(cfg_data)
        logger.info("Starting attack: %s", " ".join(cmd))

        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        health.set_status("running")
        status_gauge.set(1)
        threads_gauge.set(cfg_data.get("threads", 100))
        duration_gauge.set(cfg_data.get("duration", 60))
        rpc_gauge.set(cfg_data.get("rpc", 50))
        runs_total.inc()


def stop_attack() -> None:
    """Terminate the running Go binary if active."""
    global process

    if process and process.poll() is None:
        logger.info("Stopping attack (pid %d)", process.pid)
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            logger.warning("Process did not exit in time, killing")
            process.kill()
            process.wait()

    process = None
    health.set_status("stopped")
    status_gauge.set(0)


def _monitor_process() -> None:
    """Wait for the Go binary to exit, then update health status."""
    global process
    while not shutdown_event.is_set():
        with process_lock:
            proc = process
        if proc is not None:
            retcode = proc.poll()
            if retcode is not None:
                logger.info("Attack process exited with code %d", retcode)
                with process_lock:
                    process = None
                    status_gauge.set(0)
                if retcode == 0:
                    health.set_status("completed")
                else:
                    health.set_status("error", reason=f"exit code {retcode}")
                # If EXIT_ON_FINISH is set, shut down the container
                if os.getenv("EXIT_ON_FINISH", "1").lower() not in {"0", "false"}:
                    logger.info("Attack finished -- triggering shutdown")
                    shutdown_event.set()
                    return
        shutdown_event.wait(timeout=1)


# ── Lifecycle ──
shutdown_event = threading.Event()


def handle_shutdown(signum: int, frame) -> None:
    """Handle SIGTERM/SIGINT for clean shutdown."""
    logger.info("Received signal %d -- shutting down", signum)
    with process_lock:
        stop_attack()
    shutdown_event.set()


def main() -> None:
    # Start metrics + health server on :9090
    metrics.start_server()

    # Load initial config
    cfg_data = config.load()

    # Re-start the attack whenever config is reloaded via SIGHUP
    config.on_reload(lambda new_cfg: start_attack(new_cfg))

    # Register shutdown handlers
    signal.signal(signal.SIGTERM, handle_shutdown)
    signal.signal(signal.SIGINT, handle_shutdown)

    # Start process monitor thread
    monitor = threading.Thread(target=_monitor_process, name="process-monitor", daemon=True)
    monitor.start()

    if cfg_data:
        start_attack(cfg_data)
    else:
        logger.info("No config present -- waiting for SIGHUP with config")
        health.set_status("waiting", reason="no config")

    # Block until shutdown
    shutdown_event.wait()
    logger.info("Shutdown complete")


if __name__ == "__main__":
    main()
