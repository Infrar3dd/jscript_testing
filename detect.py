#!/usr/bin/env python3


from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterable



# Rules
@dataclass(frozen=True)
class Rule:
    tag: str               # short token used in the filename
    severity: str          # "low" | "medium" | "high" | "critical"
    pattern: re.Pattern    # compiled regex
    scope: str = "events"  # "events" | "ioc" | "both"


# Order matters only for readability; severity is aggregated independently
RULES: list[Rule] = [
    # Execution 
    Rule("powershell", "high",
         re.compile(r"\bpowershell(?:\.exe)?\b", re.I)),
    Rule("schedtask", "high",
         re.compile(r"\bschtasks(?:\.exe)?\s+/create\b", re.I)),
    Rule("certutil_decode", "high",
         re.compile(r"\bcertutil(?:\.exe)?\b[^\n]*?-decode\b", re.I)),
    Rule("execpolicy_bypass", "medium",
         re.compile(r"-ExecutionPolicy\s+(?:Bypass|Unrestricted|RemoteSigned)", re.I)),
    Rule("hidden_window", "medium",
         re.compile(r"-windowstyle\s+hidden", re.I)),
    Rule("process_run", "medium",
         re.compile(r"\[PROCESS\]\s+WScript\.Shell\.Run", re.I)),

    # Network
    Rule("http_get", "low",
         re.compile(r"\[HTTP OPEN\]\s+GET\s+\S+", re.I)),
    Rule("http_post", "medium",
         re.compile(r"\[HTTP OPEN\]\s+POST\s+\S+", re.I)),
    Rule("ps1_download", "high",
         re.compile(r"\[HTTP OPEN\]\s+GET\s+\S+\.ps1\b", re.I)),
    Rule("catbox", "medium",
         re.compile(r"https?://files\.catbox\.moe/\S+", re.I),
         scope="both"),
    Rule("firebase", "medium",
         re.compile(r"https?://firebasestorage\.googleapis\.com/\S+", re.I),
         scope="both"),

    #Persistence / staging
    Rule("copy_public", "high",
         re.compile(r"\[COPY FILE\].*?C:\\\\Users\\\\Public\\\\", re.I)),
    Rule("schedule_service", "medium",
         re.compile(r"\[ActiveXObject\]\s+Schedule\.Service", re.I)),

    #Discovery
    Rule("wmi_disk", "low",
         re.compile(r"\[WMI\].*?win32_logicaldisk", re.I)),
    Rule("wmi_os", "low",
         re.compile(r"\[WMI\].*?win32_operatingsystem", re.I)),
    Rule("reg_app_paths", "medium",
         re.compile(r"\[REG READ\].*?app paths\\\\powershell\.exe", re.I)),

    #Filesystem 
    Rule("stream_save", "medium",
         re.compile(r"\[STREAM SAVE\]\s+\S+\s+\(\d+\s+bytes\)", re.I)),

    # Guard 
    Rule("http_loop", "low",
         re.compile(r"\[HTTP\]\s+Loop detected", re.I)),
]

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_LABEL = {1: "LOW", 2: "MED", 3: "HIGH", 4: "CRIT"}



# Engine
@dataclass
class Detection:
    file: str
    event_count: int
    tags: list[str] = field(default_factory=list)
    severity: str = "clean"
    evidence: dict[str, list[str]] = field(default_factory=dict)
    suggested_name: str = ""


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def flatten(trace: dict) -> tuple[str, str]:
    #Return (events_blob, ioc_blob) as plain strings
    events = "\n".join(
        ev.get("message", "")
        for ev in trace.get("events", [])
        if isinstance(ev.get("message"), str)
    )
    ioc = trace.get("IOC", {}) or {}
    ioc_blob = "\n".join(
        [*(ioc.get("domains") or []), *(ioc.get("ips") or [])]
    )
    return events, ioc_blob


def detect(trace: dict) -> Detection:
    events_blob, ioc_blob = flatten(trace)
    det = Detection(
        file="",
        event_count=len(trace.get("events", [])),
    )

    for rule in RULES:
        if rule.scope == "events":
            target = events_blob
        elif rule.scope == "ioc":
            target = ioc_blob
        else:  # both
            target = events_blob + "\n" + ioc_blob

        matches = [
            (m.group(1) if m.groups() else m.group(0)).strip()
            for m in rule.pattern.finditer(target)
        ]
        if not matches:
            continue

        # de-duplicate evidence
        seen: set[str] = set()
        uniq = [x for x in matches if not (x in seen or seen.add(x))]

        det.tags.append(rule.tag)
        det.evidence[rule.tag] = uniq[:5]
        if SEVERITY_ORDER[rule.severity] > SEVERITY_ORDER.get(det.severity, 0):
            det.severity = rule.severity

    # Order tags by severity, then alphabetically, for a stable name
    det.tags.sort(
        key=lambda t: (
            -max(
                SEVERITY_ORDER[r.severity]
                for r in RULES
                if r.tag == t
            ),
            t,
        )
    )
    det.suggested_name = build_name(det)
    return det


def build_name(det: Detection) -> str:
    if not det.tags:
        return f"CLEAN__{short_hash(det.file)}"

    sev = SEVERITY_LABEL[SEVERITY_ORDER[det.severity]]
    tags = "_".join(det.tags[:5])          # cap length
    return f"{sev}_{tags}__{short_hash(det.file)}"


def short_hash(name: str, n: int = 8) -> str:
    #First 8 chars of the SHA-256-style stem, or the raw stem if short
    stem = Path(name).stem.split(".")[0]
    return stem[:n]


# File discovery

def iter_traces(args: Iterable[str]) -> Iterable[Path]:
    for raw in args:
        p = Path(raw)
        if p.is_dir():
            seen: set[str] = set()
            for f in sorted(p.glob("*.trace.json")):
                seen.add(f.name.removesuffix(".trace.json"))
                yield f
            for f in sorted(p.glob("*.report.json")):
                if f.name.removesuffix(".report.json") not in seen:
                    yield f
        elif p.is_file():
            yield p



# rename/copy

def safe_stem(name: str) -> str:
    #Strip characters Windows/Linux dislike in filenames
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", name)


def target_path(src: Path, det: Detection, dest_dir: Path | None,
                keep_ext: bool) -> Path:
    base = safe_stem(det.suggested_name)
    ext = src.suffix if keep_ext else ""
    new_name = f"{base}{ext}"
    folder = dest_dir if dest_dir else src.parent
    return folder / new_name


def process(path: Path, dest_dir: Path | None, copy: bool, dry: bool) -> Detection:
    trace = load_json(path)
    det = detect(trace)
    det.file = path.name

    # rebuild the name now that file is set
    det.suggested_name = build_name(det)
    dst = target_path(path, det, dest_dir, keep_ext=True)

    if dry:
        print(f"[dry] {path.name}  ->  {dst.name}")
        return det

    if copy:
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, dst)
    else:
        # Rename in place; if the target already exists, append a counter
        if dst.exists() and dst.resolve() != path.resolve():
            i = 1
            while True:
                cand = dst.with_name(f"{dst.stem}.{i}{dst.suffix}")
                if not cand.exists():
                    dst = cand
                    break
                i += 1
        path.rename(dst)
    print(f"[ok]  {path.name}  ->  {dst.name}")
    return det


# cli
def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("paths", nargs="+", help="trace/report files or directories")
    ap.add_argument("--copy", metavar="DIR", default=None,
                    help="copy renamed files into DIR instead of renaming")
    ap.add_argument("--dry-run", action="store_true",
                    help="print suggested names, touch nothing")
    args = ap.parse_args(argv[1:])

    files = list(iter_traces(args.paths))
    if not files:
        print("no trace/report files found", file=sys.stderr)
        return 2

    dest = Path(args.copy) if args.copy else None
    results: list[Detection] = []

    for p in files:
        try:
            results.append(process(p, dest, copy=bool(dest), dry=args.dry_run))
        except (json.JSONDecodeError, OSError) as exc:
            print(f"[!] {p}: {exc}", file=sys.stderr)

    # audit log
    audit = [
        {
            "file": d.file,
            "event_count": d.event_count,
            "severity": d.severity,
            "tags": d.tags,
            "suggested_name": d.suggested_name,
            "evidence": d.evidence,
        }
        for d in results
    ]
    out = Path("detections.json")
    out.write_text(json.dumps(audit, indent=2, ensure_ascii=False), "utf-8")

    # smmary
    print()
    print(f"{'severity':<9} {'tags':<50} file")
    print("-" * 100)
    for d in sorted(results, key=lambda x: -SEVERITY_ORDER.get(x.severity, 0)):
        print(f"{d.severity:<9} {','.join(d.tags)[:50]:<50} {d.file}")

    print(f"\n[done] {len(results)} file(s) processed -> {out.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))