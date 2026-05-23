#!/usr/bin/env python3
"""Request a Discord approval for an outbound draft.

Posts the draft review packet to a Discord channel or thread with native
Approve and Reject buttons attached. Waits for either:
  - the gateway interaction router to write an approval marker at
    `<repo>/discord-gateway/approvals/<sha-prefix>.json`, or
  - the configured owner replying with a typed fallback `send sha:<prefix>`.

The returned approval reference can be passed to your own outbound gate scripts
as `--discord-approval-message-id` (in the form channel_id:message_id).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "conversations"))
from config import CONFIG  # noqa: E402

SCRIPT_DIR = Path(__file__).resolve().parent
SEND_MESSAGE = SCRIPT_DIR / "send_message.py"
APPROVALS_DIR = REPO_ROOT / "discord-gateway" / "approvals"
PENDING_DIR = REPO_ROOT / "discord-gateway" / "pending"
DEFAULT_APPROVER = CONFIG.discord.owner_user_id


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_text(value: str, file_path: str) -> str:
    if file_path:
        return Path(file_path).read_text()
    return value


def load_token() -> str:
    token = os.environ.get(CONFIG.discord.token_env_var, "")
    if token:
        return token
    if CONFIG.discord.token_file and CONFIG.discord.token_file.exists():
        return CONFIG.discord.token_file.read_text().strip()
    raise SystemExit(
        f"No Discord bot token found. Set {CONFIG.discord.token_env_var} "
        "or configure discord.token_file in config.toml."
    )


def split_message(text: str, limit: int = 1850) -> list[str]:
    if len(text) <= limit:
        return [text]
    chunks = []
    remaining = text
    while remaining:
        chunk = remaining[:limit]
        split_at = max(chunk.rfind("\n\n"), chunk.rfind("\n"))
        if split_at < 400:
            split_at = limit
        chunks.append(remaining[:split_at].rstrip())
        remaining = remaining[split_at:].lstrip()
    return chunks


def send_discord_message(channel_id: str, message: str, components_json: str = "") -> str:
    cmd = [sys.executable, str(SEND_MESSAGE), "--channel-id", channel_id, "--message", message]
    if components_json:
        cmd.extend(["--components-json", components_json])
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
    if result.returncode != 0:
        raise SystemExit(f"Discord send failed: {result.stderr.strip() or result.stdout.strip()}")
    match = re.search(r"\(id:\s*(\d+|unknown)\)", result.stdout)
    if not match or match.group(1) == "unknown":
        raise SystemExit(f"Could not parse Discord message id: {result.stdout.strip()}")
    return match.group(1)


def fetch_messages(channel_id: str, token: str, after: str = "", limit: int = 50) -> list[dict]:
    query = urllib.parse.urlencode({"limit": str(limit), **({"after": after} if after else {})})
    req = urllib.request.Request(
        f"https://discord.com/api/v10/channels/{channel_id}/messages?{query}",
        headers={
            "Authorization": f"Bot {token}",
            "User-Agent": "Threadkeep/0.1",
        },
    )
    with urllib.request.urlopen(req, timeout=20) as resp:
        data = json.loads(resp.read())
    if not isinstance(data, list):
        raise RuntimeError(f"Discord fetch failed: {data}")
    return data


def find_typed_confirmation(messages: list[dict], approver_id: str, full_sha: str) -> dict | None:
    for msg in messages:
        author_id = str((msg.get("author") or {}).get("id", ""))
        if author_id != approver_id:
            continue
        content = str(msg.get("content", ""))
        match = re.search(r"\bsend\b.*\bsha\s*:\s*([a-f0-9]{12,64})\b", content, re.I | re.S)
        if match and full_sha.startswith(match.group(1).lower()):
            return msg
    return None


def check_button_marker(sha_prefix: str) -> dict | None:
    """Return the marker dict if router wrote a result for this sha prefix."""
    path = APPROVALS_DIR / f"{sha_prefix}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def clear_button_marker(sha_prefix: str) -> None:
    path = APPROVALS_DIR / f"{sha_prefix}.json"
    try:
        if path.exists():
            path.unlink()
    except Exception:
        pass


def build_components(sha_prefix: str) -> list[dict]:
    """Discord action row with Approve and Reject buttons."""
    return [
        {
            "type": 1,
            "components": [
                {
                    "type": 2,
                    "style": 3,
                    "label": "Approve",
                    "custom_id": f"approve:{sha_prefix}",
                },
                {
                    "type": 2,
                    "style": 4,
                    "label": "Reject",
                    "custom_id": f"reject:{sha_prefix}",
                },
            ],
        }
    ]


def build_packet(action: str, target: str, draft_text: str, full_sha: str, prefix_len: int) -> tuple[list[str], str]:
    prefix = full_sha[:prefix_len]
    header_lines = [
        f"**Approval requested: {action}**",
        f"**Target:** {target}",
        "",
        "**Draft:**",
    ]
    footer = [
        "",
        f"Tap Approve or Reject below. Fallback: reply exactly `send sha:{prefix}`.",
    ]
    body = "\n".join(header_lines) + "\n```text\n" + draft_text + "\n```" + "\n".join(footer)
    return split_message(body), prefix


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--channel-id", required=True, help="Discord channel or thread id to post in.")
    parser.add_argument("--draft-text", default="")
    parser.add_argument("--draft-file", default="")
    parser.add_argument("--draft-sha", default="", help="Full approved draft sha. Defaults to sha256(draft text).")
    parser.add_argument("--action", default="outbound send")
    parser.add_argument("--target", default="not specified")
    parser.add_argument("--approver-user-id", default=DEFAULT_APPROVER)
    parser.add_argument("--approval-prefix-len", type=int, default=12)
    parser.add_argument("--timeout-sec", type=int, default=1800)
    parser.add_argument("--poll-interval-sec", type=int, default=5)
    parser.add_argument("--watch-mode", choices=["buttons", "typed", "both"], default="both",
                        help="Which approval channel to honor.")
    args = parser.parse_args()

    if args.approval_prefix_len < 12:
        raise SystemExit("--approval-prefix-len must be at least 12.")

    draft_text = load_text(args.draft_text, args.draft_file)
    if not draft_text.strip():
        raise SystemExit("Draft text is required.")

    full_sha = (args.draft_sha or sha256_text(draft_text)).strip().lower()
    if not re.fullmatch(r"[a-f0-9]{64}", full_sha):
        raise SystemExit("Draft sha must be a 64-character lowercase hex sha256.")

    sha_prefix = full_sha[:args.approval_prefix_len]

    clear_button_marker(sha_prefix)

    chunks, _ = build_packet(args.action, args.target, draft_text, full_sha, args.approval_prefix_len)
    components_json = json.dumps(build_components(sha_prefix))

    prompt_ids = []
    for i, chunk in enumerate(chunks):
        cj = components_json if i == len(chunks) - 1 else ""
        prompt_ids.append(send_discord_message(args.channel_id, chunk, cj))

    token = load_token()
    deadline = time.time() + max(1, args.timeout_sec)
    newest_prompt_id = prompt_ids[-1]

    while time.time() < deadline:
        if args.watch_mode in ("buttons", "both"):
            marker = check_button_marker(sha_prefix)
            if marker:
                status = marker.get("status", "")
                if status == "approved":
                    approval_message_id = marker.get("message_id") or newest_prompt_id
                    channel_id = marker.get("channel_id") or args.channel_id
                    out = {
                        "status": "approved",
                        "via": "button",
                        "channel_id": channel_id,
                        "message_id": approval_message_id,
                        "approval_reference": f"{channel_id}:{approval_message_id}",
                        "full_sha": full_sha,
                        "sha_prefix": sha_prefix,
                        "prompt_message_ids": prompt_ids,
                    }
                    print(json.dumps(out, indent=2))
                    clear_button_marker(sha_prefix)
                    return 0
                if status == "rejected":
                    out = {
                        "status": "rejected",
                        "via": "button",
                        "channel_id": marker.get("channel_id") or args.channel_id,
                        "message_id": marker.get("message_id") or newest_prompt_id,
                        "full_sha": full_sha,
                        "sha_prefix": sha_prefix,
                        "prompt_message_ids": prompt_ids,
                    }
                    print(json.dumps(out, indent=2))
                    clear_button_marker(sha_prefix)
                    return 2

        if args.watch_mode in ("typed", "both"):
            try:
                messages = fetch_messages(args.channel_id, token, after=newest_prompt_id, limit=50)
                confirmation = find_typed_confirmation(messages, args.approver_user_id, full_sha)
            except Exception:
                confirmation = None
            if confirmation:
                approval_message_id = str(confirmation.get("id", ""))
                out = {
                    "status": "approved",
                    "via": "typed",
                    "channel_id": args.channel_id,
                    "message_id": approval_message_id,
                    "approval_reference": f"{args.channel_id}:{approval_message_id}",
                    "full_sha": full_sha,
                    "sha_prefix": sha_prefix,
                    "prompt_message_ids": prompt_ids,
                }
                print(json.dumps(out, indent=2))
                return 0

        time.sleep(max(1, args.poll_interval_sec))

    print(json.dumps({
        "status": "timeout",
        "channel_id": args.channel_id,
        "full_sha": full_sha,
        "sha_prefix": sha_prefix,
        "prompt_message_ids": prompt_ids,
    }, indent=2))
    return 1


if __name__ == "__main__":
    sys.exit(main())
