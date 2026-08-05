#!/usr/bin/env python3
"""
ELI5 explain API for Shadow the Hunter mock.

POST /eli5
  { "selection": "...", "client_context": { ... optional beat/UI state ... } }

Injects full investigation package (manifest, path, shadow, narrative, evidence)
plus the user selection, then asks Gemini for a Reddit-style ELI5.

Env:
  GEMINI_API_KEY   required
  GEMINI_MODEL     default gemini-2.0-flash (or gemini-3.5-flash-lite if set)
  ELI5_PORT        default 3107
  PACKAGE_DIR      default ./package next to this file
"""
from __future__ import annotations

import json
import os
import traceback
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PACKAGE_DIR = Path(os.environ.get("PACKAGE_DIR", ROOT / "package"))
PORT = int(os.environ.get("ELI5_PORT", "3107"))
MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
API_KEY = os.environ.get("GEMINI_API_KEY", "").strip()


def load_package() -> dict:
    out: dict = {}
    files = {
        "manifest": "manifest.json",
        "path": "path.json",
        "shadow": "shadow.json",
        "display_labels": "display-labels.json",
    }
    for key, name in files.items():
        p = PACKAGE_DIR / name
        if p.exists():
            out[key] = json.loads(p.read_text(encoding="utf-8"))
    narrative = PACKAGE_DIR / "HUNTER_NARRATIVE.md"
    if narrative.exists():
        out["hunter_narrative"] = narrative.read_text(encoding="utf-8")
    evidence_dir = PACKAGE_DIR / "evidence"
    if evidence_dir.is_dir():
        out["evidence"] = {}
        for p in evidence_dir.glob("*.json"):
            try:
                out["evidence"][p.stem] = json.loads(p.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                out["evidence"][p.stem] = {"error": "invalid json"}
    # Never load redaction-map with originals
    return out


PACKAGE = load_package()


def build_prompt(selection: str, client_context: dict | None) -> str:
    pkg = PACKAGE
    manifest = pkg.get("manifest") or {}
    path = pkg.get("path") or {}
    shadow = pkg.get("shadow") or {}
    labels = (pkg.get("display_labels") or {}).get("labels") or pkg.get("display_labels") or {}

    ctx = client_context or {}
    # Keep client context compact
    ctx_compact = {
        "current_stop": ctx.get("current_stop"),
        "current_beat_id": ctx.get("current_beat_id"),
        "beat_index": ctx.get("beat_index"),
        "room": ctx.get("room"),
        "recent_narration": ctx.get("recent_narration"),
        "last_choice": ctx.get("last_choice"),
        "tour_seconds_left": ctx.get("tour_seconds_left"),
    }

    package_blob = {
        "manifest": {
            "package_id": manifest.get("package_id"),
            "title": manifest.get("title"),
            "subtitle": manifest.get("subtitle"),
            "difficulty": manifest.get("difficulty"),
            "tags": manifest.get("tags"),
            "time_scope": manifest.get("time_scope"),
            "data_scope": manifest.get("data_scope"),
            "privacy": manifest.get("privacy"),
        },
        "primary_question": path.get("primary_question"),
        "path_steps": path.get("steps"),
        "shadow_overall_reasoning": shadow.get("overall_reasoning"),
        "shadow_final_findings": shadow.get("final_findings"),
        "shadow_steps": shadow.get("steps"),
        "hunter_narrative": pkg.get("hunter_narrative"),
        "evidence_briefs": pkg.get("evidence"),
        "display_labels": labels,
        "ui_tour_state": ctx_compact,
    }

    return f"""You are a friendly security tutor. Explain LIKE I'M FIVE (Reddit ELI5 style):
- Short sentences, concrete analogies (toasts, doorbells, phone books, hall monitors).
- No shame for not knowing. Light humor OK. Not baby-talk.
- 1 short paragraph of plain meaning, then optional "In this investigation…" tying it to the hunt.
- If the selection is already simple English, still explain why it matters *here*.
- Do NOT invent new hosts, IPs, people, or findings not in the context.
- Prefer display labels (host-primary-wifi) over raw tokens if both appear.
- If selection is a whole sentence, explain the *idea* and any jargon inside it.
- Max ~120 words unless the selection is complex.

=== FULL INVESTIGATION CONTEXT (Shadow the Hunter training package) ===
{json.dumps(package_blob, indent=2)[:120000]}

=== USER SELECTED TEXT TO EXPLAIN ===
\"\"\"{selection.strip()}\"\"\"

Explain that selection with the investigation context above.
"""


def call_gemini(prompt: str) -> str:
    if not API_KEY:
        raise RuntimeError("GEMINI_API_KEY is not set")
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{MODEL}:generateContent?key={API_KEY}"
    )
    body = {
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
        "generationConfig": {
            "temperature": 0.4,
            "maxOutputTokens": 512,
        },
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=45) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    candidates = data.get("candidates") or []
    if not candidates:
        raise RuntimeError("Gemini returned no candidates: " + json.dumps(data)[:500])
    parts = (((candidates[0] or {}).get("content") or {}).get("parts")) or []
    text = "".join(p.get("text") or "" for p in parts).strip()
    if not text:
        raise RuntimeError("Empty Gemini text")
    return text


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))

    def _cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def _json(self, code: int, obj: dict) -> None:
        raw = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?")[0] in ("/health", "/"):
            self._json(
                200,
                {
                    "status": "ok",
                    "service": "shadow-eli5",
                    "model": MODEL,
                    "has_key": bool(API_KEY),
                    "package_id": (PACKAGE.get("manifest") or {}).get("package_id"),
                },
            )
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?")[0] != "/eli5":
            self._json(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length") or "0")
            raw = self.rfile.read(length) if length else b"{}"
            payload = json.loads(raw.decode("utf-8") or "{}")
            selection = (payload.get("selection") or "").strip()
            if not selection:
                self._json(400, {"error": "selection required"})
                return
            if len(selection) > 2000:
                selection = selection[:2000]
            client_context = payload.get("client_context") or {}
            prompt = build_prompt(selection, client_context)
            explanation = call_gemini(prompt)
            self._json(
                200,
                {
                    "selection": selection,
                    "explanation": explanation,
                    "model": MODEL,
                    "package_id": (PACKAGE.get("manifest") or {}).get("package_id"),
                },
            )
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")[:800]
            self._json(502, {"error": f"Gemini HTTP {e.code}", "detail": err_body})
        except Exception as e:
            traceback.print_exc()
            self._json(500, {"error": str(e)})


def main() -> None:
    print(f"ELI5 server on 0.0.0.0:{PORT} model={MODEL} has_key={bool(API_KEY)} package={PACKAGE_DIR}")
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
