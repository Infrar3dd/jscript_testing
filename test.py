#!/usr/bin/env python3


from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import requests

BASE = os.environ.get("EMU_BASE", "http://127.0.0.1:8080")
SAMPLES_DIR = Path(os.environ.get("SAMPLES_DIR", "samples"))
OUT_DIR = Path(os.environ.get("OUT_DIR", "results"))
ELEVATED = os.environ.get("ELEVATED", "1") not in ("0", "false", "False", "")
TIMEOUT = float(os.environ.get("HTTP_TIMEOUT", "120"))
PAUSE = float(os.environ.get("PAUSE", "0.2"))
SUPPORTED = (".js", ".jse", ".txt")


def _safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)


def _save(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def process(path: Path, out_dir: Path) -> dict:
    meta = {"sample": path.name, "status": "unknown"}
    safe = _safe_name(path.name)

    #  upload
    try:
        with path.open("rb") as fh:
            r = requests.post(
                f"{BASE}/api/files",
                files={"file": (path.name, fh)},
                timeout=TIMEOUT,
            )
    except requests.RequestException as exc:
        meta["status"] = "upload_error"
        meta["error"] = str(exc)
        return meta

    if r.status_code != 200:
        meta["status"] = "upload_rejected"
        meta["http_status"] = r.status_code
        meta["error"] = r.text[:500]
        return meta

    upload = r.json()
    meta["uploadId"] = upload.get("uploadId")
    meta["source"] = upload.get("filename")
    meta["size"] = upload.get("size")

    # emulate
    try:
        r = requests.post(
            f"{BASE}/api/emulate",
            json={"uploadId": upload["uploadId"], "elevated": ELEVATED},
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        meta["status"] = "emulate_error"
        meta["error"] = str(exc)
        return meta

    if r.status_code != 200:
        meta["status"] = "emulate_rejected"
        meta["http_status"] = r.status_code
        meta["error"] = r.text[:500]
        return meta

    emu = r.json()
    run_id = emu.get("runId")
    meta["runId"] = run_id
    meta["artifacts_count"] = len(emu.get("artifacts") or [])
    meta["emulation_failed"] = "[SERVER] Emulation failed" in (emu.get("trace") or "")
    if meta["emulation_failed"]:
        meta["status"] = "emulation_failed"
    else:
        meta["status"] = "emulated"

    # trace 
    if run_id:
        try:
            r = requests.get(f"{BASE}/api/traces/{run_id}", timeout=TIMEOUT)
            if r.status_code == 200:
                _save(out_dir / f"{safe}.trace.json", r.content)
                meta["trace_saved"] = True
            else:
                meta["trace_saved"] = False
                meta["trace_http"] = r.status_code
        except requests.RequestException as exc:
            meta["trace_saved"] = False
            meta["trace_error"] = str(exc)

    # Also keep the report returned inline
    if "report" in emu:
        _save(
            out_dir / f"{safe}.report.json",
            json.dumps(emu["report"], ensure_ascii=False, indent=2).encode("utf-8"),
        )

    # artifacts
    if run_id and emu.get("artifacts"):
        try:
            r = requests.get(
                f"{BASE}/api/artifacts/{run_id}/archive",
                timeout=TIMEOUT,
            )
            if r.status_code == 200:
                _save(out_dir / f"{safe}.artifacts.zip", r.content)
                meta["artifacts_saved"] = True
            elif r.status_code == 404:
                # Race with TTL cleanup, or empty archive after all.
                meta["artifacts_saved"] = False
                meta["artifacts_note"] = r.json().get("error", "not found")
            else:
                meta["artifacts_saved"] = False
                meta["artifacts_http"] = r.status_code
        except requests.RequestException as exc:
            meta["artifacts_saved"] = False
            meta["artifacts_error"] = str(exc)
    else:
        meta["artifacts_saved"] = False
        meta["artifacts_note"] = "no artifacts reported by /api/emulate"

    return meta


def main() -> int:
    if not SAMPLES_DIR.is_dir():
        print(f"[!] samples dir not found: {SAMPLES_DIR}", file=sys.stderr)
        return 2
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # Health check
    try:
        r = requests.get(f"{BASE}/api/health", timeout=5)
        if r.status_code != 200 or r.json().get("status") != "ok":
            print(f"[!] emulator health check failed: {r.status_code} {r.text[:200]}", file=sys.stderr)
            return 2
    except requests.RequestException as exc:
        print(f"[!] cannot reach emulator at {BASE}: {exc}", file=sys.stderr)
        return 2

    samples = sorted(
        p for p in SAMPLES_DIR.iterdir()
        if p.is_file() and p.suffix.lower() in SUPPORTED
    )
    if not samples:
        print(f"[!] no samples (*{'*, *'.join(SUPPORTED)}) in {SAMPLES_DIR}", file=sys.stderr)
        return 2

    summary = {"ok": 0, "emulation_failed": 0, "other_error": 0, "with_artifacts": 0}
    metas: list[dict] = []

    for path in samples:
        print(f"[*] {path.name} ...", flush=True)
        meta = process(path, OUT_DIR)
        metas.append(meta)
        status = meta.get("status")
        if status == "emulated":
            summary["ok"] += 1
        elif status == "emulation_failed":
            summary["emulation_failed"] += 1
        else:
            summary["other_error"] += 1
        if meta.get("artifacts_saved"):
            summary["with_artifacts"] += 1
        note = meta.get("error") or meta.get("artifacts_note") or ""
        print(f"    -> {status}  runId={meta.get('runId')}  artifacts={meta.get('artifacts_saved')}"
              + (f"  ({note[:120]})" if note else ""))
        time.sleep(PAUSE)

    _save(
        OUT_DIR / "batch-summary.json",
        json.dumps({"summary": summary, "runs": metas}, ensure_ascii=False, indent=2).encode("utf-8"),
    )
    print(
        f"\n[done] ok={summary['ok']} emulation_failed={summary['emulation_failed']} "
        f"other_error={summary['other_error']} with_artifacts={summary['with_artifacts']}"
    )
    print(f"[done] results in {OUT_DIR.resolve()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())