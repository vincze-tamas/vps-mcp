import json
import os
import re
import subprocess
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel
from mcp.server.transport_security import TransportSecuritySettings

load_dotenv()

APP_DIR = Path(os.getenv("APP_DIR", "/opt/vps-mcp"))
LOG_DIR = APP_DIR / "logs"
RAW_LOG_DIR = LOG_DIR / "raw"
MCP_LOG = LOG_DIR / "mcp_exec.log"
BEARER_TOKEN = os.getenv("BEARER_TOKEN", "")
PORT = int(os.getenv("PORT", "8093"))

for path in (APP_DIR, LOG_DIR, RAW_LOG_DIR):
    path.mkdir(parents=True, exist_ok=True)

mcp = FastMCP("vps-mcp", transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False))
app = FastAPI(title="vps-mcp")
state_lock = threading.Lock()
state = {"mode": "idle", "updated_at": None, "current_command": None}
execution_starts = deque()
EXEC_WINDOW_SECONDS = 60
BLOCKED_PATTERNS = [
    r"rm\s+-rf\s+/",
    r"rm\s+-rf\s+\*",
    r"\bmkfs\b",
    r"\bdd\b",
    r"\bshutdown\b",
    r"\breboot\b",
]


def _utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')


def _prune_rate_locked(now: float) -> int:
    while execution_starts and now - execution_starts[0] > EXEC_WINDOW_SECONDS:
        execution_starts.popleft()
    return len(execution_starts)


def _read_log_entries() -> list[dict]:
    if not MCP_LOG.exists():
        return []
    entries = []
    for line in MCP_LOG.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return entries


def _write_logs(summary: dict, stdout: str, stderr: str, raw_path: Path) -> None:
    with MCP_LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(summary, ensure_ascii=False) + "\n")
    raw_path.write_text(
        "\n".join([
            "timestamp: " + summary["timestamp"],
            "command: " + summary["command"],
            "status: " + str(summary["status"]),
            "exit_code: " + str(summary["exit_code"]),
            "exec_time: " + str(summary["exec_time"]),
            "rate_1m: " + str(summary["rate_1m"]),
            "verified: " + str(summary["verified"]),
            "stdout:",
            stdout,
            "stderr:",
            stderr,
            "",
        ]),
        encoding="utf-8",
    )


def _run_exec(command: str, source: str = "agent") -> dict:
    now = time.monotonic()
    timestamp = _utc_stamp()
    with state_lock:
        execution_starts.append(now)
        rate_1m = _prune_rate_locked(now)
        state["mode"] = "executing"
        state["updated_at"] = timestamp
        state["current_command"] = command

    raw_path = RAW_LOG_DIR / f"exec_{timestamp}.log"
    started = time.monotonic()

    try:
        normalized = " ".join(command.split())
        lowered = normalized.lower()
        blocked = any(re.search(pattern, lowered) for pattern in BLOCKED_PATTERNS)
        if blocked:
            stdout = ""
            stderr = "command blocked by safety policy"
            exit_code = 1
        else:
            completed = subprocess.run(
                command,
                shell=True,
                executable="/bin/bash",
                capture_output=True,
                text=True,
                timeout=300,
                cwd=str(APP_DIR),
            )
            stdout = completed.stdout
            stderr = completed.stderr
            exit_code = completed.returncode

        exec_time = round(time.monotonic() - started, 4)
        verified = exit_code == 0 and stderr.strip() == ""
        if blocked:
            exec_status = "FAIL"
        elif verified:
            exec_status = "SUCCESS"
        elif exit_code == 0:
            exec_status = "WARNING"
        else:
            exec_status = "FAIL"

        response = {
            "status": exec_status,
            "exit_code": exit_code,
            "code": exit_code,
            "stdout": stdout,
            "stderr": stderr,
            "exec_time": exec_time,
            "rate_1m": rate_1m,
            "output_file": str(raw_path),
            "verified": verified,
            "source": source,
        }
        summary = {
            "timestamp": timestamp,
            "command": command,
            **response,
        }
        _write_logs(summary, stdout, stderr, raw_path)
        return response
    finally:
        with state_lock:
            state["mode"] = "idle"
            state["updated_at"] = _utc_stamp()
            state["current_command"] = None


@mcp.tool(name="vps_exec")
def vps_exec(command: str) -> dict:
    return _run_exec(command, source="agent")


class BearerAuthMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            path = scope.get("path", "")
            public_paths = {"/", "/health", "/status"}
            if path.startswith("/sites/") or path == "/sites":
                pass
            elif BEARER_TOKEN and path not in public_paths:
                headers = {
                    key.decode("latin-1").lower(): value.decode("latin-1")
                    for key, value in scope.get("headers", [])
                }
                if headers.get("authorization", "") != f"Bearer {BEARER_TOKEN}":
                    response = JSONResponse({"detail": "Unauthorized"}, status_code=401)
                    await response(scope, receive, send)
                    return
        await self.app(scope, receive, send)


class ExecRequest(BaseModel):
    cmd: str
    source: str = "user"


@app.post("/exec")
def http_exec(req: ExecRequest) -> JSONResponse:
    cmd = req.cmd.strip()
    if not cmd:
        return JSONResponse({"detail": "cmd is required"}, status_code=400)
    result = _run_exec(cmd, source=req.source.strip() or "user")
    return JSONResponse(result)


@app.get("/logs")
def http_logs(
    limit: int = Query(100, ge=1, le=500),
    source: str = Query("all"),
    q: str = Query(""),
    errors_only: bool = Query(False),
) -> JSONResponse:
    entries = _read_log_entries()
    entries.reverse()
    source_n = source.strip().lower()
    result: list[dict[str, Any]] = []
    for idx, e in enumerate(entries):
        entry_source = str(e.get("source", "agent")).lower()
        if source_n in ("agent", "user") and entry_source != source_n:
            continue
        cmd = e.get("command", "")
        if q and q.lower() not in cmd.lower():
            continue
        exit_code = int(e.get("exit_code", 0))
        if errors_only and exit_code == 0:
            continue
        result.append({
            "id": len(entries) - idx,
            "created_at": e.get("timestamp", ""),
            "cmd": cmd,
            "stdout": (e.get("stdout", "") or "")[:280],
            "stderr": (e.get("stderr", "") or "")[:280],
            "exit_code": exit_code,
            "code": exit_code,
            "source": entry_source,
        })
        if len(result) >= limit:
            break
    return JSONResponse(result)


@app.get("/logs/{entry_id}")
def http_log_by_id(entry_id: int) -> JSONResponse:
    entries = _read_log_entries()
    entries.reverse()
    if entry_id < 1 or entry_id > len(entries):
        return JSONResponse({"detail": "log not found"}, status_code=404)
    e = entries[len(entries) - entry_id]
    exit_code = int(e.get("exit_code", 0))
    return JSONResponse({
        "id": entry_id,
        "created_at": e.get("timestamp", ""),
        "cmd": e.get("command", ""),
        "stdout": e.get("stdout", "") or "",
        "stderr": e.get("stderr", "") or "",
        "exit_code": exit_code,
        "code": exit_code,
        "source": str(e.get("source", "agent")).lower(),
    })


@app.get("/stats")
def http_stats() -> JSONResponse:
    entries = _read_log_entries()
    entries.reverse()
    total_errors = sum(1 for e in entries if int(e.get("exit_code", 0)) != 0)
    last_50 = []
    for idx, e in enumerate(entries[:50]):
        exit_code = int(e.get("exit_code", 0))
        last_50.append({
            "id": len(entries) - idx,
            "created_at": e.get("timestamp", ""),
            "cmd": e.get("command", ""),
            "stdout": (e.get("stdout", "") or "")[:280],
            "stderr": (e.get("stderr", "") or "")[:280],
            "exit_code": exit_code,
            "code": exit_code,
            "source": str(e.get("source", "agent")).lower(),
        })
    cmd_counts: dict[str, int] = {}
    for e in entries:
        c = e.get("command", "")
        cmd_counts[c] = cmd_counts.get(c, 0) + 1
    top_commands = sorted(
        [{"cmd": k, "count": v} for k, v in cmd_counts.items()],
        key=lambda x: (-x["count"], x["cmd"]),
    )[:10]
    return JSONResponse({
        "last_50": last_50,
        "total_errors": total_errors,
        "top_commands": top_commands,
    })


@app.get("/health")
def health() -> dict:
    with state_lock:
        now = time.monotonic()
        rate_1m = _prune_rate_locked(now)
        return {
            "state": state["mode"],
            "updated_at": state["updated_at"],
            "current_command": state["current_command"],
            "rate_1m": rate_1m,
            "base_dir": str(APP_DIR),
            "mcp_ready": True,
            "sse": "/sse",
            "messages": "/messages/",
        }


@app.get("/status")
def status() -> dict:
    return health()


@app.get("/")
def root() -> dict:
    return {"service": "vps-mcp", "health": "/health", "mcp": "/sse", "messages": "/messages/"}


app.mount("/", mcp.sse_app())
app = BearerAuthMiddleware(app)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")
