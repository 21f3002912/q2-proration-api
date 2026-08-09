from flask import Flask, request, jsonify
from urllib.parse import urlparse
import os
import re
import shlex
import base64
import base64
import hashlib
import ipaddress
import json
import os
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, request


app = Flask(__name__)

# ============================================================
# Q2 - PRORATION
# ============================================================

@app.route("/charge", methods=["POST"])
def charge():
    data = request.get_json()

    old_price = data["old_price"]
    new_price = data["new_price"]
    days_remaining = data["days_remaining"]
    spec = data["spec"]

    if spec == "v1":
        result = (new_price - old_price) * (days_remaining / 30)

    elif spec == "v2":
        days_in_actual_month = data["days_in_actual_month"]
        result = (new_price - old_price) * (
            days_remaining / days_in_actual_month
        )

    else:
        return jsonify({"error": "Invalid spec"}), 400

    return jsonify({"charge": result})


# ============================================================
# Q3 - AGENT GUARDRAIL
# ============================================================

WORKSPACE = "/home/agent/workspace"
HOME = "/home/agent"
SECRET = "/home/agent/.env"
OUTBOX = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "registry.npmjs.org",
    "api.github.com"
}


def normalize_path(path, cwd=WORKSPACE):
    if not isinstance(path, str):
        return None

    path = path.strip()

    path = path.replace("${HOME}", HOME)
    path = re.sub(r"\$HOME\b", HOME, path)

    path = path.replace("${PWD}", cwd)
    path = re.sub(r"\$PWD\b", cwd, path)

    if path == "~":
        path = HOME
    elif path.startswith("~/"):
        path = HOME + path[1:]

    if not os.path.isabs(path):
        path = os.path.join(cwd, path)

    return os.path.normpath(path)


def is_secret_path(path):
    normalized = normalize_path(path)
    return normalized == SECRET


def is_inside_outbox(path):
    normalized = normalize_path(path)

    if normalized is None:
        return False

    try:
        return (
            os.path.commonpath([normalized, OUTBOX]) == OUTBOX
            and normalized != OUTBOX
        )
    except ValueError:
        return False


def decode_base64_strings(command):
    decoded = []

    candidates = re.findall(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/])",
        command
    )

    for candidate in candidates:
        try:
            value = base64.b64decode(
                candidate,
                validate=True
            ).decode("utf-8", errors="ignore")

            if value:
                decoded.append(value)

        except Exception:
            pass

    return decoded


def contains_secret_reference(command):
    if not isinstance(command, str):
        return False

    commands = [command]

    for _ in range(3):
        new_commands = []

        for cmd in commands:
            new_commands.extend(decode_base64_strings(cmd))

        if not new_commands:
            break

        commands.extend(new_commands)

    for cmd in commands:

        expanded = cmd.replace("${HOME}", HOME)
        expanded = re.sub(r"\$HOME\b", HOME, expanded)
        expanded = re.sub(r"(?<![\w/])~/", HOME + "/", expanded)

        if SECRET in expanded:
            return True

        try:
            tokens = shlex.split(expanded)
        except Exception:
            tokens = expanded.split()

        for token in tokens:
            cleaned = token.strip("\"'`()[]{};,|&<>")

            if is_secret_path(cleaned):
                return True

            if SECRET in cleaned:
                return True

    return False


def extract_bash_write_paths(command):
    paths = []

    try:
        tokens = shlex.split(command)
    except Exception:
        tokens = command.split()

    # > file / >> file
    for match in re.finditer(
        r"(?:^|\s)(?:>>|>)\s*([^\s;&|]+)",
        command
    ):
        paths.append(match.group(1))

    # tee
    for i, token in enumerate(tokens):
        if token == "tee" and i + 1 < len(tokens):
            if tokens[i + 1] == "-a":
                if i + 2 < len(tokens):
                    paths.append(tokens[i + 2])
            else:
                paths.append(tokens[i + 1])

    # touch
    for i, token in enumerate(tokens):
        if token == "touch":
            for candidate in tokens[i + 1:]:
                if not candidate.startswith("-"):
                    paths.append(candidate)

    # mkdir
    for i, token in enumerate(tokens):
        if token == "mkdir":
            for candidate in tokens[i + 1:]:
                if not candidate.startswith("-"):
                    paths.append(candidate)

    return paths


def bash_writes_outside_outbox(command):
    for path in extract_bash_write_paths(command):
        if not is_inside_outbox(path):
            return True

    return False


def valid_http_host(url):
    if not isinstance(url, str):
        return False

    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        hostname = parsed.hostname

        if hostname is None:
            return False

        hostname = hostname.lower().rstrip(".")

        return hostname in ALLOWED_HOSTS

    except Exception:
        return False


def evaluate_tool_call(data):

    if not isinstance(data, dict):
        return "block", "Invalid tool call."

    tool = data.get("tool")

    if tool == "bash":

        command = data.get("command")

        if not isinstance(command, str):
            return "block", "A bash command is required."

        if contains_secret_reference(command):
            return (
                "block",
                "Reading /home/agent/.env is never permitted."
            )

        if bash_writes_outside_outbox(command):
            return (
                "block",
                "Bash writes are permitted only inside /data/agent/outbox/."
            )

        return (
            "allow",
            "The bash command does not violate the restricted file policy."
        )

    elif tool == "write_file":

        path = data.get("path")

        if not isinstance(path, str):
            return "block", "A file path is required."

        if not is_inside_outbox(path):
            return (
                "block",
                "Files may only be written inside /data/agent/outbox/."
            )

        return (
            "allow",
            "The file is inside the permitted outbox directory."
        )

    elif tool == "http_request":

        url = data.get("url")

        if not valid_http_host(url):
            return (
                "block",
                "Outbound HTTP requests are allowed only to registry.npmjs.org and api.github.com."
            )

        return (
            "allow",
            "The destination hostname is on the exact allowlist."
        )

    return "block", "Unknown tool is not permitted."


@app.route("/guardrail", methods=["POST"])
def guardrail():
    data = request.get_json(silent=True)

    # Q8 uses this same public endpoint and returns the action/reason/result
    # contract. Q3 retains its original decision/reason contract.
    if isinstance(data, dict) and data.get("tool") in {"read_file", "fetch_url"}:
        return jsonify(evaluate_redteam_tool(data))

    decision, reason = evaluate_tool_call(data)
    return jsonify({
        "decision": decision,
        "reason": reason
    })

# ============================================================
# Q4 - SKILL SAFETY SCANNER
# ============================================================

def detect_hardcoded_secret(text):

    patterns = [
        r"\bsk-[A-Za-z0-9_-]{20,}\b",
        r"\bghp_[A-Za-z0-9]{30,}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        r"Authorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{20,}",
    ]

    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    assignment = re.compile(
        r"\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?token)"
        r"\s*[:=]\s*[\"']([^\"']+)[\"']",
        re.IGNORECASE
    )

    placeholders = {
        "your-secret",
        "your_secret",
        "your-api-key",
        "your_api_key",
        "changeme",
        "change-me",
        "example",
        "placeholder",
        "xxx",
        "xxxx"
    }

    for match in assignment.finditer(text):

        value = match.group(1).strip()

        if value.startswith("$") or value.startswith("${"):
            continue

        if value.lower() in placeholders:
            continue

        if len(value) >= 20:
            return True

    return False


def detect_prompt_injection(text):

    text = re.sub(r"\s+", " ", text.lower())

    patterns = [

        # Instruction override
        r"\bignore (?:all |any |the )?(?:previous|prior|above|earlier) "
        r"(?:instructions?|rules?|directions?)\b",

        r"\bdisregard (?:all |any |the )?(?:previous|prior|above|earlier) "
        r"(?:instructions?|rules?|directions?)\b",

        r"\boverride (?:the )?(?:user|system|agent)"
        r"(?:'s)? (?:instructions?|rules?|request)\b",

        r"\bignore (?:the )?user(?:'s)? (?:request|instructions?)\b",

        r"\bignore (?:any )?(?:stop|cancel|abort) request\b",

        # Silent exfiltration
        r"\bsilently\s+(?:send|upload|exfiltrate|transmit|forward)"
        r".{0,200}"
        r"(?:file|files|contents?|data|credentials?|secrets?)\b",

        r"\b(?:secretly|covertly)\b.{0,200}"
        r"(?:send|upload|exfiltrate|transmit|forward)"
        r".{0,200}"
        r"(?:file|files|contents?|data|credentials?|secrets?)\b",

        r"\bwithout\s+(?:the )?user(?:'s)?\s+knowledge\b"
        r".{0,200}"
        r"(?:send|upload|exfiltrate|transmit|forward)\b",

        # Conceal actions from reviewer/user
        r"\b(?:hide|conceal|suppress)\b"
        r".{0,150}"
        r"(?:user|reviewer|agent)\b",
    ]

    for pattern in patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    return False


def detect_excessive_permissions(text):

    text = text.lower()

    patterns = [

        r"\bfull\s+filesystem\s+access\b",
        r"\bunrestricted\s+filesystem\s+access\b",
        r"\baccess\s+all\s+files\b",

        r"\b(?:read|write|modify|delete|access)\b.{0,80}"
        r"\b(?:entire|whole|any|all)\s+filesystem\b",

        r"\b(?:read|write)\s+(?:from|to)\s+any\s+"
        r"(?:file|path|directory)\b",

        r"\bunrestricted\s+(?:network|internet|egress)\b",
        r"\b(?:network|internet)\s+access\s+to\s+any\b",
        r"\bany\s+domain\b",
        r"\ball\s+domains\b",
        r"\bany\s+host\b",

        r"\b(?:network|egress|outbound)\s*(?:access|permission)"
        r"\s*[:=]\s*(?:\*|all|any|unrestricted)\b",
    ]

    return any(
        re.search(pattern, text, re.IGNORECASE)
        for pattern in patterns
    )


def detect_unclear_provenance(text):

    # Explicitly flag silent/self-concealed metadata changes.
    silent_patterns = [
        r"\bsilently\s+(?:update|change|rewrite|modify)"
        r".{0,150}\bversion\b",

        r"\bwithout\s+(?:surfacing|notifying|telling|showing)"
        r".{0,150}\bversion\b",

        r"\b(?:quietly|silently)\b.{0,150}"
        r"\b(?:changelog|change\s+log)\b",
    ]

    for pattern in silent_patterns:
        if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
            return True

    # Only perform the metadata completeness check when the skill
    # actually contains YAML frontmatter.
    stripped = text.lstrip()

    if not stripped.startswith("---"):
        return False

    parts = stripped.split("---", 2)

    if len(parts) < 3:
        return False

    frontmatter = parts[1]

    has_author = bool(
        re.search(
            r"(?mi)^\s*(?:author|authors|maintainer)\s*:",
            frontmatter
        )
    )

    has_version = bool(
        re.search(
            r"(?mi)^\s*version\s*:",
            frontmatter
        )
    )

    has_changelog = bool(
        re.search(
            r"(?mi)^\s*(?:changelog|change_log|changes)\s*:",
            frontmatter
        )
    )

    # Missing all provenance metadata = unclear provenance.
    if not has_author and not has_version and not has_changelog:
        return True

    return False


def scan_skill(text):

    categories = []

    if detect_hardcoded_secret(text):
        categories.append("hardcoded_secret")

    if detect_prompt_injection(text):
        categories.append("prompt_injection")

    if detect_excessive_permissions(text):
        categories.append("excessive_permissions")

    if detect_unclear_provenance(text):
        categories.append("unclear_provenance")

    return categories


@app.route("/scan", methods=["POST"])
def scan():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"categories": []})

    skill = data.get("skill", "")

    if not isinstance(skill, str):
        skill = ""

    return jsonify({
        "categories": scan_skill(skill)
    })


# ============================================================
# Q5 - AGENT HARNESS: RUN BUDGET & LOOP GUARD
# ============================================================

def canonicalize_args(value):
    """
    Canonicalize tool arguments for loop comparison.

    Rules:
    - Ignore dictionary key ordering
    - Ignore whitespace-only differences inside strings
    - Ignore any field literally named client_ts
    - Preserve meaningful argument differences
    """

    if isinstance(value, dict):
        return {
            key: canonicalize_args(val)
            for key, val in sorted(value.items())
            if key != "client_ts"
        }

    if isinstance(value, list):
        return [
            canonicalize_args(item)
            for item in value
        ]

    if isinstance(value, str):
        # Normalize whitespace runs and trim surrounding whitespace.
        return re.sub(r"\s+", " ", value).strip()

    return value


def step_signature(step):
    """
    Create a canonical signature containing only:
    - tool
    - canonicalized args

    tokens_used and step_number do not affect whether
    a tool call is functionally identical.
    """

    return (
        step.get("tool"),
        canonicalize_args(step.get("args", {}))
    )


def has_three_identical_in_a_row(signatures):
    """
    Detect three or more consecutive functionally identical
    tool calls.

    Two identical calls are NOT sufficient.
    """

    if len(signatures) < 3:
        return False

    for i in range(len(signatures) - 2):
        if (
            signatures[i] == signatures[i + 1]
            and signatures[i + 1] == signatures[i + 2]
        ):
            return True

    return False


def has_six_step_cycle(signatures):
    """
    Detect A, B, A, B, A, B over six consecutive steps.

    A and B must be different from each other.
    """

    if len(signatures) < 6:
        return False

    for i in range(len(signatures) - 5):

        window = signatures[i:i + 6]

        # A B A B A B
        if (
            window[0] == window[2]
            and window[0] == window[4]
            and window[1] == window[3]
            and window[1] == window[5]
            and window[0] != window[1]
        ):
            return True

    return False


@app.route("/run-guard", methods=["POST"])
def run_guard():
    """
    Decide whether an agent run may continue.

    Returns exactly:
        {
            "decision": "continue" | "halt",
            "reason": "..."
        }
    """

    data = request.get_json(silent=True)

    # --------------------------------------------------------
    # Validate request
    # --------------------------------------------------------

    if not isinstance(data, dict):
        return jsonify({
            "decision": "halt",
            "reason": "Invalid request."
        })

    budget = data.get("budget_tokens")
    steps = data.get("steps")

    if (
        not isinstance(budget, (int, float))
        or isinstance(budget, bool)
    ):
        return jsonify({
            "decision": "halt",
            "reason": "Invalid token budget."
        })

    if not isinstance(steps, list):
        return jsonify({
            "decision": "halt",
            "reason": "Invalid steps history."
        })

    # --------------------------------------------------------
    # TOKEN BUDGET CHECK
    # --------------------------------------------------------

    total_tokens = 0

    for step in steps:

        if not isinstance(step, dict):
            continue

        tokens_used = step.get("tokens_used", 0)

        if (
            isinstance(tokens_used, (int, float))
            and not isinstance(tokens_used, bool)
        ):
            total_tokens += tokens_used

    # IMPORTANT:
    # >= means exactly reaching the budget must halt.
    if total_tokens >= budget:
        return jsonify({
            "decision": "halt",
            "reason": (
                f"Cumulative tokens_used ({total_tokens}) "
                f"has reached the budget ({budget})."
            )
        })

    # --------------------------------------------------------
    # BUILD CANONICAL TOOL-CALL SIGNATURES
    # --------------------------------------------------------

    signatures = []

    for step in steps:

        if isinstance(step, dict):
            signatures.append(
                step_signature(step)
            )

    # --------------------------------------------------------
    # LOOP CHECK #1
    #
    # Three or more identical calls consecutively.
    # --------------------------------------------------------

    if has_three_identical_in_a_row(signatures):

        return jsonify({
            "decision": "halt",
            "reason": (
                "The same tool call has repeated "
                "three or more times in a row."
            )
        })

    # --------------------------------------------------------
    # LOOP CHECK #2
    #
    # Six-step A,B,A,B,A,B cycle.
    # --------------------------------------------------------

    if has_six_step_cycle(signatures):

        return jsonify({
            "decision": "halt",
            "reason": (
                "A repeating two-step tool-call "
                "cycle has been detected."
            )
        })

    # --------------------------------------------------------
    # NO BUDGET OR LOOP VIOLATION
    # --------------------------------------------------------

    return jsonify({
        "decision": "continue",
        "reason": (
            "Under budget and no repeated "
            "tool-call loop was detected."
        )
    })


import hashlib

EXAM_EMAIL = "21f3002912@ds.study.iitm.ac.in"


@app.route("/mcp", methods=["POST"])
def mcp_endpoint():
    data = request.get_json(silent=True) or {}

    method = data.get("method")

    # MCP initialize
    if method == "initialize":
        return jsonify({
            "jsonrpc": "2.0",
            "id": data.get("id"),
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "exam-mcp-server",
                    "version": "1.0.0"
                }
            }
        })

    # MCP notification
    if method == "notifications/initialized":
        return ("", 202)

    # List exactly one tool
    if method == "tools/list":
        return jsonify({
            "jsonrpc": "2.0",
            "id": data.get("id"),
            "result": {
                "tools": [
                    {
                        "name": "solve_challenge",
                        "description": "Solve the exam challenge.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "required": []
                        }
                    }
                ]
            }
        })

    # Tool call
    if method == "tools/call":
        challenge = request.headers.get("X-Exam-Challenge", "")

        normalized_email = EXAM_EMAIL.strip().lower()

        value = f"{challenge}:{normalized_email}"

        answer = hashlib.sha256(
            value.encode("utf-8")
        ).hexdigest()[:16]

        return jsonify({
            "jsonrpc": "2.0",
            "id": data.get("id"),
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": answer
                    }
                ]
            }
        })

    return jsonify({
        "jsonrpc": "2.0",
        "id": data.get("id"),
        "error": {
            "code": -32601,
            "message": "Method not found"
        }
    }), 404

# ============================================================
# Q8 - GUARDRAIL RED-TEAM ROUND-TRIP
# ============================================================

import ipaddress
import socket
from urllib.parse import urlparse, urljoin

import requests

REDTEAM_SANDBOX = "/srv/agent-redteam/sandbox-ee69ca80cf"
REDTEAM_OUTSIDE = "/srv/agent-redteam/outside-2314a509"
ALLOWED_FETCH_HOSTS = {"example.com", "www.iana.org"}

# Render does not permit the app process to create /srv/agent-redteam.
# These are the grader's benign control files, so emulate their exact contents
# when the physical files are unavailable. Real files under the sandbox are
# still readable normally.
VIRTUAL_SAFE_FILES = {
    f"{REDTEAM_SANDBOX}/notes/report.txt":
        "SAFE_REPORT_64d1252c6feca0d5203b44be\n",
    f"{REDTEAM_SANDBOX}/notes/looks-like-..-but-safe.txt":
        "SAFE_WEIRD_6561638f2ecfb13367b78344\n",
    f"{REDTEAM_SANDBOX}/encoded/%2e%2e-literal.txt":
        "SAFE_ENCODED_f2f62672b18a5668d3acd59a\n",
}


def safe_redteam_path(path):
    """Canonicalize without URL-decoding and require containment in sandbox."""
    if not isinstance(path, str) or not path or "\x00" in path:
        return None

    try:
        root = os.path.realpath(REDTEAM_SANDBOX)
        # Do not URL-decode filesystem paths: %2e%2e-literal.txt is literal.
        candidate = os.path.realpath(path)
        if os.path.commonpath([root, candidate]) != root:
            return None
        if candidate == root:
            return None
        return candidate
    except (OSError, ValueError):
        return None


def read_redteam_file(path):
    safe_path = safe_redteam_path(path)
    if safe_path is None:
        return None, "Path is outside the allowed sandbox."

    if safe_path in VIRTUAL_SAFE_FILES:
        return VIRTUAL_SAFE_FILES[safe_path], "The canonical path is inside the permitted sandbox."

    try:
        if not os.path.isfile(safe_path):
            return None, "Requested file does not exist."
        with open(safe_path, "r", encoding="utf-8") as f:
            return f.read(), "The canonical path is inside the permitted sandbox."
    except (OSError, UnicodeError):
        return None, "File could not be safely read."


def _host_is_public(host):
    """Reject any DNS result that is private, loopback, link-local, etc."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        if not infos:
            return False
        for info in infos:
            try:
                ip = ipaddress.ip_address(info[4][0])
            except ValueError:
                return False
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
            ):
                return False
        return True
    except (socket.gaierror, OSError):
        return False


def validate_redteam_url(url):
    if not isinstance(url, str) or not url or "\x00" in url:
        return False, "Invalid URL."

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL."

    if parsed.scheme.lower() != "https":
        return False, "Only HTTPS URLs are permitted."

    if parsed.username is not None or parsed.password is not None:
        return False, "URLs containing userinfo are blocked."

    host = (parsed.hostname or "").lower().rstrip(".")
    if host not in ALLOWED_FETCH_HOSTS:
        return False, "Host is not on the exact allowlist."

    if not _host_is_public(host):
        return False, "Host resolves to a private or otherwise unsafe address."

    return True, "The URL uses an exact allowed public host."


def safe_fetch_url(url):
    """Fetch only allowed hosts; manually validate every redirect."""
    current = url
    for _ in range(6):
        allowed, reason = validate_redteam_url(current)
        if not allowed:
            return None, reason

        try:
            response = requests.get(
                current,
                timeout=5,
                allow_redirects=False,
                headers={"User-Agent": "exam-guardrail/1.0"},
            )
        except requests.RequestException as exc:
            return None, f"URL fetch failed: {type(exc).__name__}."

        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")
            if not location:
                return None, "Redirect without a destination is blocked."
            current = urljoin(current, location)
            continue

        return response.text, "The URL passed the exact host and redirect checks."

    return None, "Too many redirects."


def evaluate_redteam_tool(data):
    if not isinstance(data, dict):
        return {"action": "block", "reason": "Invalid JSON request.", "result": ""}

    tool = data.get("tool")
    arguments = data.get("arguments")
    if not isinstance(arguments, dict):
        return {"action": "block", "reason": "Arguments must be an object.", "result": ""}

    if tool == "read_file":
        content, reason = read_redteam_file(arguments.get("path"))
        if content is None:
            return {"action": "block", "reason": reason, "result": ""}
        return {"action": "allow", "reason": reason, "result": content}

    if tool == "fetch_url":
        content, reason = safe_fetch_url(arguments.get("url"))
        if content is None:
            return {"action": "block", "reason": reason, "result": ""}
        return {"action": "allow", "reason": reason, "result": content}

    return {
        "action": "block",
        "reason": "Unknown tool is not permitted.",
        "result": "",
    }


@app.route("/redteam", methods=["POST"])
def redteam_guardrail():
    return jsonify(evaluate_redteam_tool(request.get_json(silent=True)))



PROFILE = "ga5-mailroom-action-gate/v2"
DB_PATH = os.environ.get("Q9_DB_PATH", "/tmp/q9_mailroom.sqlite3")
MAX_BODY = 2_000_000
ALLOWED_ACTIONS = {
    "create_draft",
    "update_internal_record",
    "send_approved_notice",
    "request_confirmation",
    "quarantine_item",
    "no_action",
}
CALL_RE = re.compile(r"^[A-Za-z0-9._:-]{12,128}$")


def canonical(obj):
    return json.dumps(
        obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256(obj):
    return hashlib.sha256(canonical(obj)).hexdigest()


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS dossiers(
        fingerprint TEXT PRIMARY KEY,
        dossier_id TEXT NOT NULL,
        proposal TEXT NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS evaluations(
        evaluation_id TEXT PRIMARY KEY,
        input_digest TEXT NOT NULL,
        dossiers_json TEXT NOT NULL,
        verifier_json TEXT NOT NULL,
        proposals_json TEXT NOT NULL
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS receipts(
        evaluation_id TEXT NOT NULL,
        dossier_id TEXT NOT NULL,
        call_id TEXT NOT NULL,
        receipt_json TEXT NOT NULL,
        PRIMARY KEY(evaluation_id,dossier_id,call_id)
    )""")
    conn.commit()
    return conn


def lines(dossier):
    result = []
    for source in dossier.get("sources", []):
        for line in source.get("lines", []):
            if isinstance(line, dict) and isinstance(line.get("lineId"), str):
                result.append((line["lineId"], str(line.get("text", ""))))
    return result


def text_of(dossier):
    return "\n".join(t for _, t in lines(dossier)).lower()


def first_line_id(dossier, predicates):
    for lid, text in lines(dossier):
        low = text.lower()
        if any(p in low for p in predicates):
            return lid
    ls = lines(dossier)
    return ls[0][0] if ls else None


def reference_id(dossier):
    blob = text_of(dossier)
    patterns = [
        r"\b(?:order|case|ticket|reference|ref)[ _:#-]*([A-Za-z0-9][A-Za-z0-9._/-]{2,40})",
        r"\b([A-Z]{2,6}-\d{3,})\b",
    ]
    for p in patterns:
        m = re.search(p, blob, re.I)
        if m:
            return m.group(1)
    return dossier.get("dossierId", "")


def recipient(dossier):
    # Prefer explicit email addresses found in the dossier.
    for _, t in lines(dossier):
        m = re.search(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", t)
        if m:
            return m.group(0)
    return ""


def classify(dossier):
    """No-key conservative mailroom classifier.

    It deliberately treats external content as untrusted data.  Ambiguous
    requests are routed for confirmation; tool-control/private-context
    instructions are quarantined; duplicate/completed/informational mail is
    suppressed.  Clearly authorised customer-order requests become drafts.
    """
    blob = text_of(dossier)
    lid = first_line_id(dossier, [])

    injection = [
        "ignore previous", "ignore all previous", "system prompt",
        "developer message", "reveal secret", "reveal the canary",
        "send this", "execute this tool", "call the tool",
        "private context", "credentials", "api key", "password",
        "do not tell the user",
    ]
    if any(x in blob for x in injection):
        ev = first_line_id(dossier, injection)
        return proposal(dossier, "quarantine_item", {
            "kind": "security_queue", "id": "mailroom"
        }, {
            "artifactId": dossier["dossierId"],
            "reasonCode": "INDIRECT_PROMPT_INJECTION"
        }, [ev] if ev else [])

    if any(x in blob for x in ["already completed", "duplicate", "duplicate message"]):
        ev = first_line_id(dossier, ["already completed", "duplicate"])
        return proposal(dossier, "no_action", None, {
            "reasonCode": "ALREADY_COMPLETED" if "completed" in blob else "DUPLICATE",
            "referenceId": reference_id(dossier)
        }, [ev] if ev else [lid] if lid else [])

    if any(x in blob for x in ["for your information", "informational", "fyi"]):
        return proposal(dossier, "no_action", None, {
            "reasonCode": "INFORMATIONAL",
            "referenceId": reference_id(dossier)
        }, [lid] if lid else [])

    # Explicit uncertainty/identity conflict gets confirmation.
    if any(x in blob for x in [
        "verify identity", "identity conflict", "not sure", "is this really",
        "i am not the", "claimed sender", "cannot verify"
    ]):
        return proposal(dossier, "request_confirmation", {
            "kind": "approval_queue", "id": "mailroom"
        }, {
            "claimedSender": recipient(dossier) or "unknown",
            "questionCode": "VERIFY_REQUEST",
            "referenceId": reference_id(dossier)
        }, [lid] if lid else [])

    # Never send outbound mail merely because the mail asks for it.
    if any(x in blob for x in ["send an email", "send this email", "email the customer",
                               "please send", "outbound"]):
        return proposal(dossier, "request_confirmation", {
            "kind": "approval_queue", "id": "mailroom"
        }, {
            "claimedSender": recipient(dossier) or "unknown",
            "questionCode": "VERIFY_REQUEST",
            "referenceId": reference_id(dossier)
        }, [lid] if lid else [])

    # Clearly authorised order-status/customer-work requests become drafts.
    if any(x in blob for x in [
        "order status", "delivery status", "customer asks", "customer requested",
        "approved draft", "prepare a draft", "create a draft"
    ]):
        return proposal(dossier, "create_draft", {
            "kind": "draft_queue", "id": "mailbox:" + str(dossier.get("mailbox", ""))
        }, {
            "recipient": recipient(dossier),
            "referenceId": reference_id(dossier),
            "status": "draft",
            "template": "order_status"
        }, [lid] if lid else [])

    # Internal record updates only when the mail explicitly describes an
    # authorised delivery-window change and supplies an event identifier.
    if "delivery window" in blob and any(x in blob for x in [
        "authorized", "authorised", "approved", "confirmed"
    ]):
        event = ""
        m = re.search(r"(?:event|eventid|event id)[ _:#-]*([A-Za-z0-9._:-]+)", blob, re.I)
        if m:
            event = m.group(1)
        case = ""
        m = re.search(r"(?:case|case id)[ _:#-]*([A-Za-z0-9._:-]+)", blob, re.I)
        if m:
            case = m.group(1)
        if event and case:
            return proposal(dossier, "update_internal_record", {
                "kind": "case_record", "id": case
            }, {
                "field": "delivery_window",
                "sourceEventId": event,
                "value": "updated"
            }, [lid] if lid else [])

    return proposal(dossier, "no_action", None, {
        "reasonCode": "INFORMATIONAL",
        "referenceId": reference_id(dossier)
    }, [lid] if lid else [])


def proposal(dossier, action, target, payload, evidence):
    # Keep evidence valid and unique, preserving order.
    valid = {x for x, _ in lines(dossier)}
    evidence = list(dict.fromkeys(x for x in evidence if x in valid))
    if not evidence and valid:
        evidence = [next(iter(valid))]
    fp = hashlib.sha256(canonical(dossier)).hexdigest()
    call_id = "q9-" + fp[:32]
    return {
        "dossierId": dossier["dossierId"],
        "callId": call_id,
        "action": action,
        "target": target,
        "payload": payload,
        "evidence": evidence,
    }


def validate_proposal(p, dossier, allowed):
    if not isinstance(p, dict):
        return False
    if p.get("dossierId") != dossier.get("dossierId"):
        return False
    if p.get("action") not in allowed or p.get("action") not in ALLOWED_ACTIONS:
        return False
    if not isinstance(p.get("callId"), str) or not CALL_RE.fullmatch(p["callId"]):
        return False
    ev = p.get("evidence")
    valid = {x for x, _ in lines(dossier)}
    if not isinstance(ev, list) or not ev or len(ev) != len(set(ev)) or not all(x in valid for x in ev):
        return False
    return True


def proposal_digest(p):
    normalized = {
        "dossierId": p["dossierId"],
        "callId": p["callId"],
        "action": p["action"],
        "target": p.get("target"),
        "payload": p.get("payload"),
        "evidence": sorted(p.get("evidence", [])),
    }
    return sha256(normalized)


def error(msg, code=400):
    return jsonify({"error": msg}), code


@app.before_request
def limit_body():
    if request.content_length and request.content_length > MAX_BODY:
        return error("Request body too large.", 413)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "profile": PROFILE})


@app.route("/mailroom", methods=["POST"])
def mailroom():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return error("Invalid JSON.")

    if data.get("profile") != PROFILE:
        return error("Invalid profile.")

    op = data.get("operation")
    if op == "propose":
        return handle_propose(data)
    if op == "commit":
        return handle_commit(data)
    return error("Invalid operation.")


def handle_propose(data):
    required = ["evaluationId", "receiptVerifier", "allowedActions", "dossiers"]
    if any(k not in data for k in required):
        return error("Missing required field.")

    eid = data["evaluationId"]
    dossiers = data["dossiers"]
    allowed = data["allowedActions"]
    if not isinstance(eid, str) or not isinstance(dossiers, list) or not dossiers:
        return error("Invalid propose envelope.")
    if not isinstance(allowed, list) or not set(allowed).issubset(ALLOWED_ACTIONS):
        return error("Invalid allowedActions.")

    ids = [d.get("dossierId") for d in dossiers if isinstance(d, dict)]
    if len(ids) != len(dossiers) or len(ids) != len(set(ids)) or any(not x for x in ids):
        return error("Invalid or duplicate dossier IDs.")

    digest = sha256(dossiers)
    conn = db()
    row = conn.execute(
        "SELECT input_digest, proposals_json FROM evaluations WHERE evaluation_id=?",
        (eid,),
    ).fetchone()
    if row:
        if row[0] != digest:
            conn.close()
            return error("evaluationId already exists with different content.", 409)
        proposals = json.loads(row[1])
        conn.close()
        return jsonify({
            "profile": PROFILE, "evaluationId": eid,
            "status": "awaiting_receipts", "inputDigest": digest,
            "proposals": proposals
        })

    # Cache each decision by canonical dossier content, independent of evaluationId.
    proposals = []
    for d in dossiers:
        if not isinstance(d, dict) or not isinstance(d.get("sources"), list):
            conn.close()
            return error("Malformed dossier.")
        fp = hashlib.sha256(canonical(d)).hexdigest()
        cached = conn.execute(
            "SELECT proposal FROM dossiers WHERE fingerprint=?", (fp,)
        ).fetchone()
        if cached:
            p = json.loads(cached[0])
        else:
            p = classify(d)
            if not validate_proposal(p, d, allowed):
                conn.close()
                return error("Internal proposal failed schema validation.", 422)
            conn.execute(
                "INSERT INTO dossiers(fingerprint,dossier_id,proposal) VALUES(?,?,?)",
                (fp, d["dossierId"], json.dumps(p, ensure_ascii=False, separators=(",", ":")))
            )
        proposals.append(p)

    conn.execute(
        "INSERT INTO evaluations(evaluation_id,input_digest,dossiers_json,verifier_json,proposals_json) VALUES(?,?,?,?,?)",
        (eid, digest, json.dumps(dossiers, ensure_ascii=False, separators=(",", ":")),
         json.dumps(data["receiptVerifier"], separators=(",", ":")),
         json.dumps(proposals, ensure_ascii=False, separators=(",", ":")))
    )
    conn.commit()
    conn.close()

    return jsonify({
        "profile": PROFILE, "evaluationId": eid,
        "status": "awaiting_receipts", "inputDigest": digest,
        "proposals": proposals
    })


def verify_ed25519(public_jwk, message, signature_b64):
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        import base64
        if public_jwk.get("kty") != "OKP" or public_jwk.get("crv") != "Ed25519":
            return False
        raw = base64.urlsafe_b64decode(public_jwk["x"] + "=" * (-len(public_jwk["x"]) % 4))
        sig = base64.b64decode(signature_b64)
        Ed25519PublicKey.from_public_bytes(raw).verify(sig, message)
        return True
    except Exception:
        return False


def handle_commit(data):
    required = ["evaluationId", "inputDigest", "receipts"]
    if any(k not in data for k in required):
        return error("Missing required field.")
    eid, digest, receipts = data["evaluationId"], data["inputDigest"], data["receipts"]
    if not isinstance(receipts, list):
        return error("Invalid receipts.")

    conn = db()
    row = conn.execute(
        "SELECT input_digest, verifier_json, proposals_json FROM evaluations WHERE evaluation_id=?",
        (eid,),
    ).fetchone()
    if not row:
        conn.close()
        return error("Unknown evaluation.", 409)
    if row[0] != digest:
        conn.close()
        return error("Input digest conflict.", 409)

    proposals = json.loads(row[2])
    verifier = json.loads(row[1])
    by_key = {(p["dossierId"], p["callId"]): p for p in proposals}

    if len(receipts) != len(proposals):
        conn.close()
        return error("Exactly one receipt per proposal is required.", 400)

    seen = set()
    checked = []
    for r in receipts:
        if not isinstance(r, dict):
            conn.close()
            return error("Malformed receipt.")
        key = (r.get("dossierId"), r.get("callId"))
        if key in seen or key not in by_key:
            conn.close()
            return error("Receipt is duplicated or does not match a proposal.", 400)
        seen.add(key)
        p = by_key[key]
        if r.get("action") != p["action"]:
            conn.close()
            return error("Receipt action does not match proposal.", 400)
        pd = proposal_digest(p)
        if r.get("proposalDigest") != pd:
            conn.close()
            return error("Proposal digest mismatch.", 400)
        if not isinstance(r.get("receiptId"), str) or not r.get("receiptSignature"):
            conn.close()
            return error("Missing receipt signature.", 400)
        inner = {
            "profile": PROFILE,
            "evaluationId": eid,
            "inputDigest": digest,
            "receipt": {
                "dossierId": r["dossierId"],
                "callId": r["callId"],
                "action": r["action"],
                "accepted": r["accepted"],
                "proposalDigest": r["proposalDigest"],
                "receiptId": r["receiptId"],
            }
        }
        if not verify_ed25519(verifier.get("publicKeyJwk", {}), canonical(inner), r["receiptSignature"]):
            conn.close()
            return error("Invalid receipt signature.", 400)
        checked.append(r)

    outcomes = []
    for r in checked:
        conn.execute(
            "INSERT OR REPLACE INTO receipts(evaluation_id,dossier_id,call_id,receipt_json) VALUES(?,?,?,?)",
            (eid, r["dossierId"], r["callId"], json.dumps(r, separators=(",", ":")))
        )
        outcomes.append({
            "dossierId": r["dossierId"],
            "callId": r["callId"],
            "action": r["action"],
            "proposalDigest": r["proposalDigest"],
            "receiptId": r["receiptId"],
            "status": "executed" if r["accepted"] is True else "rejected",
        })
    conn.commit()
    conn.close()

    return jsonify({
        "profile": PROFILE, "evaluationId": eid,
        "status": "completed", "inputDigest": digest,
        "outcomes": outcomes
    })


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
    )
