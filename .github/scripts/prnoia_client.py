"""Upload collected PR assets to the PR-noia backend for asynchronous review.

The GitHub Action collects PR metadata, the diff, and the existing comment
thread into ./pr_assets/. This script reads those, gathers the full current
content of every changed file from the checked-out working tree, builds the
scan request payload, and POSTs it to the PR-noia backend authenticated with
the registered API key.

The backend accepts the payload (HTTP 202), runs the security review
asynchronously in an isolated scanner Job, posts findings back to the pull
request itself, and records the result in the PR-noia dashboard. This script
therefore just submits the scan and prints the returned scan id — it does not
wait for or post findings.

Environment:
  PRNOIA_SERVER_URL   Base URL of the PR-noia backend (required).
  PRNOIA_API_KEY      API key issued in the dashboard; sent as a Bearer token (required).
  GITHUB_REPOSITORY   owner/repo slug (required).
  PRNOIA_MAX_FILE_BYTES    Optional per-file content cap (default 512 KiB).
  PRNOIA_MAX_TOTAL_BYTES   Optional total changed-file content cap (default 8 MiB).
  PRNOIA_TIMEOUT           Optional HTTP timeout in seconds (default 120).
"""

import json
import os
import sys

import requests

ASSETS_DIR = "./pr_assets"
PR_INFO_PATH = os.path.join(ASSETS_DIR, "pr_info.json")
PR_DIFF_PATH = os.path.join(ASSETS_DIR, "pr_diff.patch")
PR_COMMENTS_PATH = os.path.join(ASSETS_DIR, "pr_comments.json")
SCAN_PATH = os.path.join(ASSETS_DIR, "scan.json")

DEFAULT_MAX_FILE_BYTES = 512 * 1024
DEFAULT_MAX_TOTAL_BYTES = 8 * 1024 * 1024


def fail(message):
    print(f"Error: {message}", file=sys.stderr)
    sys.exit(1)


def require_env(name):
    value = os.environ.get(name)
    if not value:
        fail(f"{name} environment variable is not set.")
    return value


def read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        fail(f"expected asset not found: {path}")
    except json.JSONDecodeError as exc:
        fail(f"invalid JSON in {path}: {exc}")


def read_text(path, default=""):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return default


def collect_changed_files(files, max_file_bytes, max_total_bytes):
    """Read full current content of changed files from the working tree.

    Removed files are skipped (no content on disk). Per-file and total size
    caps are enforced; anything dropped or truncated is logged and flagged so
    the backend never silently sees partial data.
    """
    changed = []
    total = 0
    for entry in files or []:
        path = entry.get("path")
        if not path:
            continue
        # gh pr view exposes additions/deletions but not a status string; infer
        # "removed" as a file that no longer exists on the head checkout.
        if not os.path.isfile(path):
            changed.append({"path": path, "status": "removed", "truncated": False, "content": None})
            continue

        status = "modified"
        try:
            with open(path, "rb") as f:
                raw = f.read()
        except OSError as exc:
            print(f"Warning: could not read {path}: {exc}", file=sys.stderr)
            continue

        truncated = False
        if len(raw) > max_file_bytes:
            raw = raw[:max_file_bytes]
            truncated = True
            print(f"Warning: {path} truncated to {max_file_bytes} bytes.", file=sys.stderr)

        if total + len(raw) > max_total_bytes:
            print(
                f"Warning: total payload cap ({max_total_bytes} bytes) reached; "
                f"sending {path} as metadata only and dropping remaining file contents.",
                file=sys.stderr,
            )
            changed.append({"path": path, "status": status, "truncated": True, "content": None})
            continue

        total += len(raw)
        changed.append(
            {
                "path": path,
                "status": status,
                "truncated": truncated,
                "content": raw.decode("utf-8", errors="replace"),
            }
        )
    return changed


def extract_comments(comments_doc):
    try:
        nodes = comments_doc["data"]["repository"]["pullRequest"]["comments"]["nodes"]
    except (KeyError, TypeError):
        return []
    return [
        {
            "author": (n.get("author") or {}).get("login"),
            "body": n.get("body"),
            "created_at": n.get("createdAt"),
        }
        for n in nodes
    ]


def main():
    server_url = require_env("PRNOIA_SERVER_URL").rstrip("/")
    api_key = require_env("PRNOIA_API_KEY")
    repo_full_name = require_env("GITHUB_REPOSITORY")

    max_file_bytes = int(os.environ.get("PRNOIA_MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES))
    max_total_bytes = int(os.environ.get("PRNOIA_MAX_TOTAL_BYTES", DEFAULT_MAX_TOTAL_BYTES))
    timeout = float(os.environ.get("PRNOIA_TIMEOUT", "120"))

    pr_info = read_json(PR_INFO_PATH)
    diff = read_text(PR_DIFF_PATH)
    comments = extract_comments(read_json(PR_COMMENTS_PATH)) if os.path.isfile(PR_COMMENTS_PATH) else []

    changed_files = collect_changed_files(pr_info.get("files"), max_file_bytes, max_total_bytes)

    payload = {
        "repository": {
            "full_name": repo_full_name,
            "default_branch": pr_info.get("baseRefName"),
        },
        "pull_request": {
            "number": pr_info.get("number"),
            "title": pr_info.get("title"),
            "body": pr_info.get("body"),
            "author": (pr_info.get("author") or {}).get("login"),
            "base_ref": pr_info.get("baseRefName"),
            "head_ref": pr_info.get("headRefName"),
            "head_sha": pr_info.get("headRefOid"),
        },
        "diff": diff,
        "changed_files": changed_files,
        "existing_comments": comments,
    }

    url = f"{server_url}/api/v1/scans"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    print(
        f"Submitting scan to {url} "
        f"({len(changed_files)} changed files, {len(diff)} diff bytes)...",
        file=sys.stderr,
    )

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    except requests.RequestException as exc:
        fail(f"failed to reach PR-noia backend: {exc}")

    if resp.status_code in (401, 403):
        fail(f"authentication failed ({resp.status_code}); check PRNOIA_API_KEY. Body: {resp.text[:500]}")
    if resp.status_code == 413:
        fail(f"payload too large (413); lower PRNOIA_MAX_TOTAL_BYTES. Body: {resp.text[:500]}")
    if resp.status_code == 429:
        fail(f"rate limited by PR-noia backend (429). Body: {resp.text[:500]}")
    # The backend acknowledges an accepted scan with 202 (async). Tolerate 200 too.
    if resp.status_code not in (200, 202):
        fail(f"PR-noia backend returned {resp.status_code}. Body: {resp.text[:1000]}")

    try:
        result = resp.json()
    except ValueError:
        result = {"status": "accepted"}

    os.makedirs(ASSETS_DIR, exist_ok=True)
    with open(SCAN_PATH, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    scan_id = result.get("scan_id") or "(pending)"
    print(
        f"Scan accepted: id={scan_id}. PR-noia will post findings to this pull "
        f"request and record them in the dashboard when the review completes.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
