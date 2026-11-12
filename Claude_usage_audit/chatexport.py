#!/usr/bin/env python3
"""
chatexport.py -- shared reader for claude.ai conversation exports.

Both exact_count.py and claude_token_audit.py import this. That is the whole
point: the two tools must agree exactly on (a) which conversation is which,
(b) which message is which, and (c) what text a message contains. When that
logic was duplicated across both files, the sidecar silently mismatched.

Keep all three files in the same directory.
"""

import json
from pathlib import Path

SCHEMA = 3  # bump when keys, text extraction or count semantics change
            # (3: per-request overhead subtracted, empty messages = 0)


def flatten(content):
    """Pull plain text out of the several shapes message content can take."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        for key in ("text", "content", "input", "thinking"):
            if key in content:
                return flatten(content[key])
        return json.dumps(content)
    if isinstance(content, list):
        return "\n".join(flatten(c) for c in content)
    return str(content)


def conversation_key(conv, position):
    """A key that is stable across runs and unique within an export.

    Prefer the export's own identifier. Fall back to file position, which is
    stable for a given export file. Never key on title alone: duplicate and
    untitled conversations collide, and the sidecar then applies one
    conversation's token counts to another's messages.
    """
    for field in ("uuid", "id", "conversation_id"):
        value = conv.get(field)
        if value:
            return str(value)
    return f"#{position}"


def conversation_name(conv):
    return conv.get("name") or conv.get("title") or "(untitled)"


def load(path):
    """Yield (key, name, conv_dict, [(index, role, text, attach_chars), ...]).

    attach_chars is how many characters of `text` came from attachments. It is
    surfaced separately so the insight layer can estimate attachment token
    share, but `text` itself is unchanged -- exact_count's content hashes stay
    stable, so existing sidecars remain valid.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        data = data.get("conversations") or data.get("data") or [data]

    for position, conv in enumerate(data):
        if not isinstance(conv, dict):
            continue
        msgs = (conv.get("chat_messages") or conv.get("messages")
                or conv.get("mapping") or [])
        if isinstance(msgs, dict):
            msgs = list(msgs.values())

        turns = []
        for index, msg in enumerate(msgs):
            if not isinstance(msg, dict):
                continue
            if "message" in msg and isinstance(msg["message"], dict):
                msg = msg["message"]
            role = (msg.get("sender") or msg.get("role")
                    or (msg.get("author") or {}).get("role") or "")
            text = flatten(msg.get("text") or msg.get("content")
                           or msg.get("parts"))
            attach_chars = 0
            for att in (msg.get("attachments") or []):
                if isinstance(att, dict):
                    extra = flatten(att.get("extracted_content"))
                    text += extra
                    attach_chars += len(extra)
            turns.append((index, str(role).lower(), text, attach_chars))

        if turns:
            yield conversation_key(conv, position), conversation_name(conv), conv, turns


def sidecar_path(export_path):
    return Path(export_path).with_suffix(".tokens.json")


def read_sidecar(export_path):
    """Return {conv_key: {msg_index: tokens}} or None."""
    path = sidecar_path(export_path)
    if not path.exists():
        return None
    try:
        blob = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None
    if blob.get("schema") != SCHEMA:
        print(f"  ! {path.name} was written by an older schema; "
              f"re-run exact_count.py")
        return None
    return blob.get("counts") or None


def write_sidecar(export_path, model, counts):
    path = sidecar_path(export_path)
    path.write_text(json.dumps({"schema": SCHEMA, "model": model,
                                "counts": counts}), encoding="utf-8")
    return path
