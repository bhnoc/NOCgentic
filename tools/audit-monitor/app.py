"""
audit-monitor — Live view of BHNOCgentic agent spans from S3.

Deploys on the EC2 host (which has the S3 instance role). Access is gated
behind a shared bearer token that exchanges for a signed HTTPOnly cookie.

Mount path behind nginx: /bh/1337/thetraces/

Run:
    python tools/audit-monitor/app.py

Environment:
    AUDIT_BUCKET          — default: blackhat-pope-dev-logs
    AUDIT_PREFIX          — default: nocgentic/traces
    AUDIT_REGION          — default: us-west-2
    AUDIT_HOST            — default: 0.0.0.0
    AUDIT_PORT            — default: 8787
    AUDIT_POLL_S          — default: 2
    AUDIT_LOOKBACK        — default: 300 (initial lookback seconds)
    AUDIT_ROOT_PATH       — default: ""  (set to /bh/1337/thetraces when behind nginx)
    AUDIT_BEARER_TOKEN    — shared secret (required, no default — server refuses to start if missing)
    AUDIT_COOKIE_SECRET   — HMAC key for cookie signing (default: ephemeral per-process random secret)
    AUDIT_COOKIE_TTL      — cookie lifetime in seconds (default: 86400 = 24h)
    AWS_PROFILE           — forwarded to boto3 if set
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import hashlib
import hmac
import json
import logging
import os
import secrets
import sys
import time
import webbrowser
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import boto3
import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    StreamingResponse,
)
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

# --- Config ---------------------------------------------------------------

BUCKET   = os.getenv("AUDIT_BUCKET", "blackhat-pope-dev-logs")
PREFIX   = os.getenv("AUDIT_PREFIX", "nocgentic/traces").strip("/")
REGION   = os.getenv("AUDIT_REGION", "us-west-2")
HOST     = os.getenv("AUDIT_HOST", "0.0.0.0")
PORT     = int(os.getenv("AUDIT_PORT", "8787"))
POLL_S   = float(os.getenv("AUDIT_POLL_S", "2"))
LOOKBACK = int(os.getenv("AUDIT_LOOKBACK", "300"))
ROOT_PATH = os.getenv("AUDIT_ROOT_PATH", "").rstrip("/")

BEARER_TOKEN    = os.getenv("AUDIT_BEARER_TOKEN", "")
COOKIE_TTL      = int(os.getenv("AUDIT_COOKIE_TTL", "86400"))
COOKIE_NAME = "bh_audit"

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] audit-monitor: %(message)s",
)
log = logging.getLogger("audit-monitor")

# Cookie signing secret. SAFE-BY-DEFAULT: never empty, and never derived from
# the bearer token (a blank bearer used to yield "" here, making the HMAC
# forgeable — fail-OPEN). Use the configured secret if present, otherwise mint
# a strong ephemeral per-process secret so cookies remain unforgeable even when
# unconfigured.
_cookie_secret = os.getenv("AUDIT_COOKIE_SECRET") or ""
if not _cookie_secret:
    _cookie_secret = secrets.token_urlsafe(32)
    log.warning(
        "no AUDIT_COOKIE_SECRET set — using ephemeral per-process secret; "
        "sessions won't survive restart"
    )


def _s3():
    session_kwargs: dict[str, str] = {}
    profile = os.getenv("AWS_PROFILE")
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(region_name=REGION, **session_kwargs)
    return session.client("s3")


# --- Cookie / token helpers ----------------------------------------------

def _sign_cookie(expiry_ts: int) -> str:
    """Return a compact signed cookie value: <expiry>.<hmac>."""
    payload = str(expiry_ts).encode()
    sig = hmac.new(_cookie_secret.encode(), payload, hashlib.sha256).digest()
    return f"{expiry_ts}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"


def _verify_cookie(value: str) -> bool:
    if not value or "." not in value:
        return False
    try:
        expiry_str, sig_b64 = value.split(".", 1)
        expiry_ts = int(expiry_str)
    except (ValueError, IndexError):
        return False
    if expiry_ts < int(time.time()):
        return False
    expected = _sign_cookie(expiry_ts).split(".", 1)[1]
    return secrets.compare_digest(expected, sig_b64)


def _request_authorized(request: Request) -> bool:
    # 1) Valid bearer header authorizes any call
    auth_hdr = request.headers.get("authorization", "")
    if auth_hdr.lower().startswith("bearer "):
        token = auth_hdr.split(" ", 1)[1].strip()
        if BEARER_TOKEN and secrets.compare_digest(token, BEARER_TOKEN):
            return True
    # 2) Otherwise require a valid session cookie
    return _verify_cookie(request.cookies.get(COOKIE_NAME, ""))


# --- In-memory buffer + subscribers --------------------------------------

recent_events: deque[dict[str, Any]] = deque(maxlen=2000)
subscribers: list[asyncio.Queue] = []
last_seen_key: dict[str, str] = {}   # service_prefix → last processed key


def _classify_span(span: dict[str, Any]) -> dict[str, Any]:
    name = (span.get("name") or "").lower()
    attrs = span.get("attributes") or {}
    resource = span.get("resource") or {}

    kind = "span"
    if any(k.startswith("gen_ai") for k in attrs) or "langsmith.span.kind" in attrs or "llm" in name:
        kind = "llm"
    elif "athena" in name or "executequery" in name.replace("_", ""):
        kind = "athena"
    elif name.startswith("post ") or name.startswith("get ") or "http" in name:
        kind = "http"
    elif "tool" in name or "execute_sql" in name:
        kind = "tool"
    elif name.endswith(".analyze") or name.endswith(".triage") or name.endswith(".query") \
        or name.endswith(".classify") or "agent" in name:
        kind = "agent"

    service = (
        resource.get("service.name")
        or attrs.get("service.name")
        or "unknown"
    )
    short_svc = str(service).replace("bhnocgentic-", "")
    return {
        "service": short_svc,
        "kind": kind,
        "name": span.get("name"),
        "trace_id": span.get("trace_id"),
        "span_id": span.get("span_id"),
        "parent_span_id": span.get("parent_span_id"),
        "duration_ms": span.get("duration_ms"),
        "start_time": span.get("start_time"),
        "end_time": span.get("end_time"),
        "status_code": span.get("status_code"),
        "attributes": attrs,
        "events": span.get("events") or [],
        "resource_service": service,
    }


def _extract_service_prefixes(s3) -> list[str]:
    resp = s3.list_objects_v2(
        Bucket=BUCKET,
        Prefix=f"{PREFIX}/",
        Delimiter="/",
    )
    services = []
    for cp in resp.get("CommonPrefixes") or []:
        p = cp.get("Prefix", "")
        if "service=" in p:
            services.append(p)
    return services


def _initial_start_after(service_prefix: str) -> str:
    start = datetime.now(timezone.utc) - timedelta(seconds=LOOKBACK)
    dt = start.strftime("%Y-%m-%d")
    hour = start.strftime("%H")
    ts = start.strftime("%Y%m%dT%H%M%S")
    return f"{service_prefix}dt={dt}/hour={hour}/aaaa-{ts}-00000000.jsonl.gz"


async def _poll_once(s3, service_prefixes: list[str]) -> None:
    for sp in service_prefixes:
        start_after = last_seen_key.get(sp) or _initial_start_after(sp)
        kwargs = {"Bucket": BUCKET, "Prefix": sp, "MaxKeys": 100, "StartAfter": start_after}
        try:
            resp = await asyncio.to_thread(s3.list_objects_v2, **kwargs)
        except Exception as exc:
            log.warning("list_objects_v2 failed for %s: %s", sp, exc)
            continue
        # Only advance the cursor past the highest CONTIGUOUS successfully-
        # processed key. If a key fails mid-batch, stop advancing so the next
        # poll retries it. Otherwise a later key's success would jump the cursor
        # past the failure and permanently drop it from the "permanent" audit
        # trail (cc-3). S3 lists keys in lexicographic order, so breaking on the
        # first failure leaves the cursor at the last good key and the next poll
        # re-lists from there.
        for obj in resp.get("Contents") or []:
            key = obj["Key"]
            try:
                body = await asyncio.to_thread(
                    lambda k=key: s3.get_object(Bucket=BUCKET, Key=k)["Body"].read()
                )
                raw = gzip.decompress(body).decode("utf-8", errors="replace")
                for line in raw.splitlines():
                    if not line.strip():
                        continue
                    try:
                        span = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    event = _classify_span(span)
                    event["_source_key"] = key
                    recent_events.append(event)
                    for q in list(subscribers):
                        try:
                            q.put_nowait(event)
                        except asyncio.QueueFull:
                            pass
                last_seen_key[sp] = key
            except Exception as exc:
                log.warning("failed to fetch/parse %s: %s; retrying next poll", key, exc)
                break


async def preload(timeout_s: float = 15.0) -> None:
    async def _do():
        s3 = _s3()
        service_prefixes = await asyncio.to_thread(_extract_service_prefixes, s3)
        log.info("preload: discovered %d services, fetching last %ds",
                 len(service_prefixes), LOOKBACK)
        await _poll_once(s3, service_prefixes)
        log.info("preload: %d spans cached", len(recent_events))
    try:
        await asyncio.wait_for(_do(), timeout=timeout_s)
    except asyncio.TimeoutError:
        log.warning("preload timed out after %.0fs", timeout_s)
    except Exception as exc:
        log.warning("preload failed: %s", exc)


async def poll_loop() -> None:
    service_prefixes: list[str] = []
    last_discover = 0.0
    while True:
        # Fresh client per cycle — instance-role creds rotate ~every 6 h and
        # a cached client hangs onto the old session token.
        s3 = _s3()
        now = asyncio.get_event_loop().time()
        if now - last_discover > 30 or not service_prefixes:
            try:
                service_prefixes = await asyncio.to_thread(_extract_service_prefixes, s3)
                last_discover = now
            except Exception as exc:
                log.warning("service discovery failed: %s", exc)
        try:
            await _poll_once(s3, service_prefixes)
        except Exception as exc:
            log.warning("poll cycle failed: %s", exc)
        await asyncio.sleep(POLL_S)


# --- FastAPI --------------------------------------------------------------

app = FastAPI(
    title="BHNOCgentic audit-monitor",
    version="0.1.0",
    root_path=ROOT_PATH,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


class AuthMiddleware(BaseHTTPMiddleware):
    """
    Require a valid session cookie or Bearer header on every request except:
      - GET /login  (serves login page)
      - POST /login (exchanges token for cookie)
      - /healthz    (container health probe)
    """

    PUBLIC_PATHS = {"/login", "/healthz"}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        # Normalise: strip root_path if present (starlette may or may not strip)
        if ROOT_PATH and path.startswith(ROOT_PATH):
            path = path[len(ROOT_PATH):] or "/"

        if path in self.PUBLIC_PATHS:
            return await call_next(request)

        if _request_authorized(request):
            return await call_next(request)

        # Unauthorized responses:
        if path.startswith("/api/") or path == "/api":
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        # HTML requests → send login page inline (simpler than redirect)
        return _login_response(request)


app.add_middleware(AuthMiddleware)


# --- Routes ---------------------------------------------------------------

def _login_response(request: Request, error: str | None = None) -> HTMLResponse:
    html = _LOGIN_HTML.replace("__ERROR__", f'<div class="error">{error}</div>' if error else "")
    return HTMLResponse(html, status_code=401 if error else 200)


@app.get("/login", include_in_schema=False)
async def login_page(request: Request) -> HTMLResponse:
    return _login_response(request)


@app.post("/login", include_in_schema=False)
async def login_submit(request: Request) -> Response:
    if not BEARER_TOKEN:
        return JSONResponse({"error": "server misconfigured — no bearer token set"}, status_code=500)
    form = await request.form()
    token = (form.get("token") or "").strip()
    if not token or not secrets.compare_digest(token, BEARER_TOKEN):
        return _login_response(request, error="Invalid token")

    expiry = int(time.time()) + COOKIE_TTL
    cookie_val = _sign_cookie(expiry)
    redirect_path = (ROOT_PATH or "") + "/"
    resp = RedirectResponse(url=redirect_path, status_code=303)
    resp.set_cookie(
        key=COOKIE_NAME,
        value=cookie_val,
        max_age=COOKIE_TTL,
        httponly=True,
        secure=True,
        samesite="lax",
        path=(ROOT_PATH + "/") if ROOT_PATH else "/",
    )
    return resp


@app.post("/logout", include_in_schema=False)
async def logout() -> Response:
    redirect_path = (ROOT_PATH or "") + "/login"
    resp = RedirectResponse(url=redirect_path, status_code=303)
    resp.delete_cookie(
        key=COOKIE_NAME,
        path=(ROOT_PATH + "/") if ROOT_PATH else "/",
    )
    return resp


@app.get("/healthz", include_in_schema=False)
async def healthz() -> PlainTextResponse:
    return PlainTextResponse("ok")


@app.get("/", include_in_schema=False)
async def root() -> Response:
    idx = STATIC_DIR / "index.html"
    if idx.exists():
        return FileResponse(idx)
    return JSONResponse({"error": "static/index.html not found"})


# Serve static assets under /assets (must be auth'd by middleware above)
if STATIC_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR)), name="assets")


# --- Admin endpoints — proxy to orchestrator (auth enforced by middleware)

ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://orchestrator:8001")
# The orchestrator's /admin/* now requires this bearer (QA sweep 2). Forward it
# on every proxied admin call, else the orchestrator returns 401.
ADMIN_BEARER_TOKEN = os.getenv("ADMIN_BEARER_TOKEN", "")


def _orch_admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_BEARER_TOKEN}"} if ADMIN_BEARER_TOKEN else {}


@app.get("/admin/killswitch")
async def admin_get_killswitch() -> Any:
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.get(f"{ORCHESTRATOR_URL}/admin/killswitch", headers=_orch_admin_headers())
        r.raise_for_status()
        return r.json()


def _has_valid_bearer(request: Request) -> bool:
    """True only for a valid Bearer *header* — not a session cookie."""
    auth_hdr = request.headers.get("authorization", "")
    if not auth_hdr.lower().startswith("bearer "):
        return False
    token = auth_hdr.split(" ", 1)[1].strip()
    return bool(BEARER_TOKEN) and secrets.compare_digest(token, BEARER_TOKEN)


@app.post("/admin/killswitch/athena")
async def admin_set_athena(request: Request) -> Any:
    # Defence-in-depth: this state-changing admin route requires a valid Bearer
    # HEADER, not just the viewer's session cookie. A stolen/forged cookie (or a
    # logged-in operator's browser) cannot flip the kill-switch on its own.
    if not _has_valid_bearer(request):
        return JSONResponse({"error": "bearer token required"}, status_code=401)
    body = await request.json()
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.post(f"{ORCHESTRATOR_URL}/admin/killswitch/athena", json=body,
                              headers=_orch_admin_headers())
        r.raise_for_status()
        return r.json()


@app.get("/admin/lanemode")
async def admin_get_lanemode() -> Any:
    """Current lane mode for the settings gear. Read-only, so cookie auth is enough."""
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.get(f"{ORCHESTRATOR_URL}/admin/lanemode", headers=_orch_admin_headers())
        r.raise_for_status()
        return r.json()


@app.post("/admin/lanemode")
async def admin_set_lanemode(request: Request) -> Any:
    # Same defence-in-depth as the kill-switch: a state change needs a real Bearer
    # HEADER, not just the viewer's session cookie. Switching the box to local-only
    # mid-demo is not something a stolen cookie should be able to do.
    if not _has_valid_bearer(request):
        return JSONResponse({"error": "bearer token required"}, status_code=401)
    body = await request.json()
    async with httpx.AsyncClient(timeout=5) as client:
        r = await client.post(f"{ORCHESTRATOR_URL}/admin/lanemode", json=body,
                              headers=_orch_admin_headers())
        # Pass the orchestrator's refusal through rather than raising: a 400 for an
        # unknown mode should reach the panel as that message.
        return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/admin/models")
async def admin_get_models() -> Any:
    """What each local endpoint is serving, plus the supervisor's allowlist."""
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(f"{ORCHESTRATOR_URL}/admin/models", headers=_orch_admin_headers())
        r.raise_for_status()
        return r.json()


@app.post("/admin/models/{action}")
async def admin_model_control(action: str, request: Request) -> Any:
    """Start or stop a local model. Bearer header required.

    `action` is checked against a literal set before it reaches the URL, so a path
    segment from the request can never steer the proxied call somewhere else.
    """
    if action not in ("start", "stop"):
        return JSONResponse({"error": "unknown action"}, status_code=404)
    if not _has_valid_bearer(request):
        return JSONResponse({"error": "bearer token required"}, status_code=401)
    body = await request.json()
    # Loading a GGUF is slow; the orchestrator's own timeout is 15s, so allow for it
    # plus a margin rather than timing out the proxy first and reporting a failure
    # for a start that actually succeeded.
    async with httpx.AsyncClient(timeout=20) as client:
        r = await client.post(f"{ORCHESTRATOR_URL}/admin/models/{action}", json=body,
                              headers=_orch_admin_headers())
        return JSONResponse(r.json(), status_code=r.status_code)


@app.get("/api/recent")
async def recent(limit: int = 200):
    # limit<=0 would slice as list[-0:] == whole buffer, so treat it as empty.
    if limit <= 0:
        return {"events": [], "count": 0}
    items = list(recent_events)[-limit:]
    return {"events": items, "count": len(items)}


@app.get("/api/services")
async def services():
    seen = sorted({e["service"] for e in recent_events})
    return {"services": seen}


@app.get("/api/stream")
async def stream():
    q: asyncio.Queue = asyncio.Queue(maxsize=500)
    subscribers.append(q)

    async def gen():
        try:
            recent_snapshot = list(recent_events)
            if recent_snapshot:
                yield f"event: snapshot\ndata: {json.dumps(recent_snapshot, default=str)}\n\n"
            while True:
                ev = await q.get()
                yield f"event: span\ndata: {json.dumps(ev, default=str)}\n\n"
        except asyncio.CancelledError:
            pass
        finally:
            try:
                subscribers.remove(q)
            except ValueError:
                pass

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# --- Startup --------------------------------------------------------------

@app.on_event("startup")
async def _startup() -> None:
    if not BEARER_TOKEN:
        log.warning(
            "AUDIT_BEARER_TOKEN unset — trace viewer is LOCKED (deny-all). "
            "Set AUDIT_BEARER_TOKEN + AUDIT_COOKIE_SECRET to enable."
        )
    await preload()
    asyncio.create_task(poll_loop())


# --- Login page (inline HTML) ---------------------------------------------

_LOGIN_HTML = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>Audit Monitor // Auth</title>
<style>
  :root {
    --bg: #030712;
    --bg-2: #0a1220;
    --border: #182a47;
    --ice: #1e90ff;
    --frost: #00d4ff;
    --text: #d8e6f5;
    --muted: #6d85a8;
    --red: #ff3050;
    --font: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; background: var(--bg); color: var(--text); font-family: var(--font); }
  body { display: flex; align-items: center; justify-content: center; }
  .box {
    background: var(--bg-2);
    border: 1px solid var(--border);
    padding: 32px 36px;
    width: 380px;
    max-width: 92vw;
    border-radius: 3px;
    box-shadow: 0 20px 80px rgba(0,212,255,0.08);
  }
  h1 {
    font-size: 14px; color: var(--frost); margin: 0 0 4px;
    text-transform: uppercase; letter-spacing: 0.15em;
    text-shadow: 0 0 10px rgba(0,212,255,0.4);
  }
  .sub { font-size: 11px; color: var(--muted); letter-spacing: 0.08em; margin-bottom: 22px; }
  label { display: block; font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.12em; margin-bottom: 6px; }
  input[type=password], input[type=text] {
    width: 100%; padding: 10px 12px; background: var(--bg); color: var(--text);
    border: 1px solid var(--border); border-radius: 2px; font-family: var(--font); font-size: 13px;
    outline: none;
  }
  input:focus { border-color: var(--ice); box-shadow: 0 0 8px rgba(30,144,255,0.2); }
  button {
    width: 100%; margin-top: 14px; padding: 10px; background: transparent; color: var(--ice);
    border: 1px solid var(--ice); border-radius: 2px; cursor: pointer;
    font-family: var(--font); font-size: 11px; text-transform: uppercase; letter-spacing: 0.15em;
  }
  button:hover { background: rgba(30,144,255,0.1); color: var(--frost); border-color: var(--frost); }
  .error { margin-top: 10px; color: var(--red); font-size: 11px; }
  .footer { margin-top: 22px; font-size: 10px; color: var(--muted); text-align: center; }
</style>
</head><body>
  <form class="box" method="POST" action="login">
    <h1>BHNOC // Audit</h1>
    <div class="sub">Token required for access</div>
    <label for="t">Bearer Token</label>
    <input id="t" name="token" type="password" autocomplete="off" autofocus />
    <button type="submit">Authenticate</button>
    __ERROR__
    <div class="footer">bhnocgentic trace audit monitor</div>
  </form>
</body></html>
"""


# --- Entry ----------------------------------------------------------------

def _check_aws_creds() -> str:
    try:
        ident = boto3.client("sts", region_name=REGION).get_caller_identity()
        return f"OK ({ident.get('Arn', '?')})"
    except Exception as exc:
        return f"NOT CONFIGURED ({type(exc).__name__})"


def main() -> None:
    print("=" * 70)
    print(" BHNOCgentic audit-monitor")
    print("=" * 70)
    print(f" S3:        s3://{BUCKET}/{PREFIX}/  ({REGION})")
    print(f" Poll:      every {POLL_S}s   Lookback: {LOOKBACK}s")
    print(f" AWS:       {_check_aws_creds()}")
    print(f" Listen:    http://{HOST}:{PORT}")
    print(f" RootPath:  {ROOT_PATH or '(none)'}")
    print(f" Auth:      {'bearer+cookie OK' if BEARER_TOKEN else '*** NO BEARER TOKEN — all requests will 401 ***'}")
    print("=" * 70)
    if ROOT_PATH == "" and HOST in ("127.0.0.1", "localhost"):
        try:
            webbrowser.open(f"http://localhost:{PORT}", new=2)
        except Exception:
            pass
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
