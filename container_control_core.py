# container_control_core.py  (v1.1 ‑ adds /api/update)
from __future__ import annotations

import importlib, logging, os, signal, sys, threading, time
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Dict, Optional

import psutil, uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel
from ruamel.yaml import YAML

# ---------- Logging (UTC) -------------------------------------------------- #
logging.Formatter.converter = time.gmtime          # type: ignore[attr-defined]
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)sZ %(levelname)s %(name)s — %(message)s",
    datefmt="%Y‑%m-%dT%H:%M:%S",
)
log = logging.getLogger("container_control_core")

# ---------- Load YAML configuration --------------------------------------- #
CFG = YAML(typ="safe").load(Path(os.getenv("CCC_CONFIG_FILE", "config.yaml")).read_text())

ADAPTER_PATH  = CFG["adapter"]["class"]            # dotted path
PRIMARY_KEY   = CFG["adapter"]["primary_payload_key"]
RUN_AS_USER   = CFG["adapter"].get("run_as_user")  # may be null

# ---------- Dynamic import ------------------------------------------------- #
modname, clsname = ADAPTER_PATH.rsplit(".", 1)
try:
    mod: ModuleType = importlib.import_module(modname)
    AdapterCls      = getattr(mod, clsname)
except Exception as exc:  # noqa: BLE001
    log.critical("Cannot import adapter %s: %s", ADAPTER_PATH, exc)
    sys.exit(1)

adapter = AdapterCls(CFG.get("adapter", {}))       # pyright: ignore[reportGeneralTypeIssues]

# ---------- Runtime state -------------------------------------------------- #
state: Dict[str, str] = {"app_status": "initializing", "container_status": "running"}
current_handle: Optional[Any] = None

# ---------- Helpers -------------------------------------------------------- #
def _now() -> str: return datetime.now(tz=UTC).isoformat().replace("+00:00", "Z")

def _ensure_user(cmd: list[str]) -> list[str]:
    if RUN_AS_USER and os.geteuid() == 0:
        return ["sudo", "-E", "-u", RUN_AS_USER, "--"] + cmd
    return cmd

def _thread(fn, *args):  # fire‑and‑forget helper
    t = threading.Thread(target=fn, args=args, daemon=True); t.start(); return t

# ---------- FastAPI App ---------------------------------------------------- #
app = FastAPI(title="Container Control Core", version="1.1")

class StartBody(BaseModel): __root__: Dict[str, Any]       # permissive
class UpdateBody(BaseModel): __root__: Dict[str, Any]
class StopBody(BaseModel): force: Optional[bool] = False

# ---------- Lifecycle glue ------------------------------------------------- #
def _start(payload: dict):
    global current_handle
    try:
        adapter.pre_start_hooks(payload)
        current_handle = adapter.start(payload, ensure_user=_ensure_user)  # type: ignore[arg-type]
        state["app_status"] = "running"
    except Exception:
        log.exception("Start failed")
        state["app_status"] = "error"

def _stop():
    global current_handle
    try:
        adapter.stop(); adapter.post_stop_hooks()
        state["app_status"] = "stopped"; current_handle = None
    except Exception:
        log.exception("Stop failed"); state["app_status"] = "error"

# ---------- API endpoints -------------------------------------------------- #
@app.get("/api/health")
async def health(): return {"status": "healthy", "app_status": state["app_status"]}

@app.post("/api/start")
async def api_start(body: dict):
    if PRIMARY_KEY not in body:
        raise HTTPException(400, f"missing key '{PRIMARY_KEY}'")
    if state["app_status"] == "running": _stop()
    state["app_status"] = "initializing"
    _thread(_start, body)
    return {"message": "start initiated"}

@app.post("/api/update")
async def api_update(body: dict):
    if state["app_status"] != "running":
        raise HTTPException(400, "application not running")
    try:
        updated = adapter.update(body)  # returns bool
    except NotImplementedError:
        raise HTTPException(409, "live‑update not supported") from None
    except Exception as exc:
        log.exception("adapter.update failed")
        raise HTTPException(500, str(exc))
    if updated:
        return {"message": "update applied"}
    raise HTTPException(409, "adapter declined update")

@app.post("/api/stop")
async def api_stop(_: StopBody):
    if state["app_status"] != "running":
        return {"message": "nothing to stop"}
    _thread(_stop); return {"message": "stop initiated"}

@app.get("/api/metrics")
async def api_metrics():
    cpu = psutil.cpu_percent()
    mem = psutil.virtual_memory()
    net = psutil.net_io_counters()
    return JSONResponse({
        "timestamp": _now(),
        "app_status": state["app_status"],
        "container_status": state["container_status"],
        "network": dict(bytes_sent=net.bytes_sent, bytes_recv=net.bytes_recv,
                        packets_sent=net.packets_sent, packets_recv=net.packets_recv),
        "system": dict(cpu_percent=round(cpu,1), memory_percent=round(mem.percent,1),
                       memory_available_mb=round(mem.available/1_048_576,2),
                       memory_used_mb=round(mem.used/1_048_576,2)),
        "metrics": adapter.get_metrics() or {},
    })

@app.get("/metrics")
async def prom():
    mem, cpu, net = psutil.virtual_memory(), psutil.cpu_percent(), psutil.net_io_counters()
    out = [
        "# HELP container_cpu_percent CPU usage %", f"container_cpu_percent {cpu}",
        "# HELP container_memory_percent Mem usage %", f"container_memory_percent {mem.percent}",
        "# HELP container_memory_used_bytes Used bytes", f"container_memory_used_bytes {mem.used}",
        "# HELP container_network_bytes_sent_total Bytes sent", f"container_network_bytes_sent_total {net.bytes_sent}",
        "# HELP container_network_bytes_recv_total Bytes recv", f"container_network_bytes_recv_total {net.bytes_recv}",
    ]
    if hasattr(adapter, "prometheus_metrics"):
        out.extend(adapter.prometheus_metrics())
    return Response("\n".join(out)+"\n", media_type="text/plain; version=0.0.4")

# ---------- Graceful shutdown --------------------------------------------- #
def _sig(_s, _f):
    log.info("signal received, shutting down")
    if state["app_status"] == "running": _stop()
    sys.exit(0)

signal.signal(signal.SIGTERM, _sig); signal.signal(signal.SIGINT, _sig)

if __name__ == "__main__":
    uvicorn.run("container_control_core:app", host="0.0.0.0", port=8080, loop="uvloop")
