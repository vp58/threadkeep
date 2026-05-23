#!/usr/bin/env python3
"""Approval responder.

Invoked by the Discord interaction router when the owner clicks Approve or
Reject on a draft preview. Writes a marker file under the gateway approvals dir
so the in-flight worker (which is polling request_approval.py) sees the result.

Marker file path:
    <repo>/discord-gateway/approvals/<sha-prefix>.json

Marker contents:
    {
        "status": "approved" | "rejected",
        "sha_prefix": "<12+ hex>",
        "channel_id": "...",
        "message_id": "...",
        "ts": "ISO8601"
    }

CLI:
    request_approval_responder.py approve --sha <prefix> --channel-id <cid> --message-id <mid>
    request_approval_responder.py reject  --sha <prefix> --channel-id <cid> --message-id <mid>
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
APPROVALS_DIR = REPO_ROOT / "discord-gateway" / "approvals"


def write_marker(status: str, sha: str, channel_id: str, message_id: str) -> Path:
    APPROVALS_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "status": status,
        "sha_prefix": sha,
        "channel_id": channel_id,
        "message_id": message_id,
        "ts": datetime.now(timezone.utc).isoformat(),
    }
    path = APPROVALS_DIR / f"{sha}.json"
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(payload, indent=2))
    tmp.replace(path)
    return path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["approve", "reject"])
    parser.add_argument("--sha", required=True)
    parser.add_argument("--channel-id", default="")
    parser.add_argument("--message-id", default="")
    args = parser.parse_args()

    sha = args.sha.strip().lower()
    if len(sha) < 8:
        print("sha prefix too short", file=sys.stderr)
        return 2

    status = "approved" if args.action == "approve" else "rejected"
    path = write_marker(status, sha, args.channel_id, args.message_id)
    print(f"{status}: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
