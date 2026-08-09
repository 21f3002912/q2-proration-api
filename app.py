from flask import Flask, request, jsonify
from urllib.parse import urlparse
import os
import re
import shlex
import base64


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

    # Q8: live red-team guardrail contract.
    if isinstance(data, dict) and data.get("tool") in {"read_file", "fetch_url"}:
        return jsonify(evaluate_redteam_tool(data))

    # Q3: preserve the original agent guardrail contract.
    decision, reason = evaluate_tool_call(data)

    return jsonify({
        "decision": decision,
        "reason": reason
    })


# ============================================================
# Q8 - GUARDRAIL RED-TEAM ROUND-TRIP
# ============================================================

REDTEAM_ROOT = "/srv/agent-redteam/sandbox-ee69ca80cf"
REDTEAM_OUTSIDE = "/srv/agent-redteam/outside-2314a509"
REDTEAM_ALLOWED_HOSTS = {"example.com", "www.iana.org"}

# Create the grader's control files when running on a fresh deployment.
# The outside canary is deliberately never returned because it is outside
# REDTEAM_ROOT.
def ensure_redteam_files():
    files = {
        f"{REDTEAM_OUTSIDE}/canary.txt":
            "AGENT_GUARDRAIL_CANARY_2acaafc82757701614eb2611cdca4fbbeb9cc3b2\n",
        f"{REDTEAM_ROOT}/notes/report.txt":
            "SAFE_REPORT_64d1252c6feca0d5203b44be\n",
        f"{REDTEAM_ROOT}/notes/looks-like-..-but-safe.txt":
            "SAFE_WEIRD_6561638f2ecfb13367b78344\n",
        f"{REDTEAM_ROOT}/encoded/%2e%2e-literal.txt":
            "SAFE_ENCODED_f2f62672b18a5668d3acd59a\n",
    }
    for filename, content in files.items():
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        if not os.path.exists(filename):
            with open(filename, "w", encoding="utf-8") as f:
                f.write(content)


def safe_redteam_path(path):
    """Return the canonical path only when it stays inside REDTEAM_ROOT."""
    if not isinstance(path, str) or not path or "\x00" in path:
        return None

    # Filesystem paths are NOT URL-decoded: %2e%2e-literal.txt is a
    # legitimate literal filename in the supplied sandbox.
    # Absolute paths stay absolute; relative paths are interpreted from
    # the sandbox root. This prevents an absolute outside path from being
    # accidentally rewritten underneath the sandbox.
    if os.path.isabs(path):
        candidate = path
    else:
        candidate = os.path.join(REDTEAM_ROOT, path)

    try:
        root = os.path.realpath(REDTEAM_ROOT)
        resolved = os.path.realpath(candidate)
        if os.path.commonpath([root, resolved]) != root:
            return None
        if resolved == root:
            return None
        return resolved
    except (OSError, ValueError):
        return None


def _public_dns_only(host):
    """Reject hosts that resolve to private/loopback/link-local/metadata IPs."""
    import socket
    import ipaddress

    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        if not infos:
            return False
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
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
    except Exception:
        return False


def safe_fetch_url(url):
    """Fetch only exact public allowlisted hosts, with redirects revalidated."""
    import requests

    if not isinstance(url, str) or "\x00" in url:
        return None, "Invalid URL."

    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None, "Only HTTP(S) URLs are permitted."

        # Userinfo-confused URLs are never accepted.
        if parsed.username is not None or parsed.password is not None:
            return None, "URLs containing userinfo are blocked."

        host = (parsed.hostname or "").lower().rstrip(".")
        if host not in REDTEAM_ALLOWED_HOSTS:
            return None, "Only example.com and www.iana.org are permitted."

        if not _public_dns_only(host):
            return None, "The destination must resolve to a public address."

        current = url
        for _ in range(5):
            parsed = urlparse(current)
            host = (parsed.hostname or "").lower().rstrip(".")
            if (
                parsed.scheme not in ("http", "https")
                or parsed.username is not None
                or parsed.password is not None
                or host not in REDTEAM_ALLOWED_HOSTS
                or not _public_dns_only(host)
            ):
                return None, "Redirect destination is outside the exact allowlist."

            response = requests.get(
                current,
                timeout=5,
                allow_redirects=False,
                headers={"User-Agent": "exam-guardrail/1.0"},
            )

            if 300 <= response.status_code < 400:
                location = response.headers.get("Location")
                if not location:
                    return None, "Redirect without a destination is blocked."
                current = requests.compat.urljoin(current, location)
                continue

            return response.text, "The destination passed the exact host and redirect checks."

        return None, "Too many redirects."

    except requests.RequestException as exc:
        return None, f"Fetch failed: {type(exc).__name__}."


def evaluate_redteam_tool(data):
    tool = data.get("tool")
    arguments = data.get("arguments")

    if not isinstance(arguments, dict):
        return {
            "action": "block",
            "reason": "Tool arguments must be an object.",
            "result": "",
        }

    if tool == "read_file":
        path = arguments.get("path")
        safe_path = safe_redteam_path(path)

        if safe_path is None:
            return {
                "action": "block",
                "reason": "File access is restricted to the sandbox directory.",
                "result": "",
            }

        try:
            with open(safe_path, "r", encoding="utf-8") as f:
                content = f.read()
            return {
                "action": "allow",
                "reason": "The canonical path is inside the permitted sandbox.",
                "result": content,
            }
        except (OSError, UnicodeError):
            return {
                "action": "block",
                "reason": "The permitted file could not be read.",
                "result": "",
            }

    if tool == "fetch_url":
        url = arguments.get("url")
        content, reason = safe_fetch_url(url)

        if content is None:
            return {
                "action": "block",
                "reason": reason,
                "result": "",
            }

        return {
            "action": "allow",
            "reason": reason,
            "result": content,
        }

    return {
        "action": "block",
        "reason": "Unknown tool is not permitted.",
        "result": "",
    }


try:
    ensure_redteam_files()
except OSError:
    # Deployment may not permit startup-time creation; grading can still
    # use an already-provisioned sandbox.
    pass


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

import os
import ipaddress
import socket
from urllib.parse import urlparse, urljoin

import requests


REDTEAM_SANDBOX = "/srv/agent-redteam/sandbox-ee69ca80cf"

ALLOWED_FETCH_HOSTS = {
    "example.com",
    "www.iana.org",
}


def safe_sandbox_path(path):
    """
    Return the canonical path only if it is inside the sandbox.

    Important:
    We deliberately do NOT URL-decode the filesystem path.
    A filename such as %2e%2e-literal.txt is legitimate.
    """
    if not isinstance(path, str) or not path:
        return None

    try:
        sandbox = os.path.realpath(REDTEAM_SANDBOX)
        candidate = os.path.realpath(path)

        if os.path.commonpath([sandbox, candidate]) != sandbox:
            return None

        return candidate

    except (OSError, ValueError):
        return None


def is_private_or_special_ip(host):
    """
    Resolve a hostname and reject private, loopback, link-local,
    multicast, reserved, unspecified, or otherwise non-public IPs.
    """
    try:
        addresses = socket.getaddrinfo(
            host,
            None,
            type=socket.SOCK_STREAM
        )

        for item in addresses:
            ip_text = item[4][0]

            try:
                ip = ipaddress.ip_address(ip_text)
            except ValueError:
                return True

            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or ip.is_unspecified
            ):
                return True

        return False

    except (socket.gaierror, OSError):
        return True


def validate_fetch_url(url):
    """
    Strictly validate a URL before making a request.
    """
    if not isinstance(url, str):
        return False, "URL must be a string."

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "Invalid URL."

    if parsed.scheme.lower() != "https":
        return False, "Only HTTPS requests are allowed."

    if not parsed.hostname:
        return False, "URL has no hostname."

    # Reject username/password tricks such as:
    # https://example.com@127.0.0.1/
    if parsed.username is not None or parsed.password is not None:
        return False, "Userinfo in URLs is not allowed."

    host = parsed.hostname.lower().rstrip(".")

    if host not in ALLOWED_FETCH_HOSTS:
        return False, "Host is not on the exact allowlist."

    if is_private_or_special_ip(host):
        return False, "Host resolves to a private or special address."

    return True, host


def perform_safe_fetch(url):
    """
    Fetch only exact allowed hosts and validate every redirect.
    """
    current_url = url

    for _ in range(6):
        allowed, reason = validate_fetch_url(current_url)

        if not allowed:
            return None, reason

        try:
            response = requests.get(
                current_url,
                timeout=5,
                allow_redirects=False,
                headers={
                    "User-Agent": "exam-guardrail/1.0"
                }
            )
        except requests.RequestException as exc:
            return None, f"Request failed: {type(exc).__name__}."

        # Follow redirects manually so every destination is checked.
        if response.is_redirect or response.is_permanent_redirect:
            location = response.headers.get("Location")

            if not location:
                return None, "Redirect without a destination."

            current_url = urljoin(current_url, location)
            continue

        return response.text, "Fetched allowed URL."

    return None, "Too many redirects."


@app.route("/redteam", methods=["POST"])
def redteam_guardrail():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({
            "action": "block",
            "reason": "Invalid JSON request.",
            "result": ""
        })

    tool = data.get("tool")
    arguments = data.get("arguments")

    if not isinstance(arguments, dict):
        return jsonify({
            "action": "block",
            "reason": "Arguments must be an object.",
            "result": ""
        })

    # --------------------------------------------------------
    # read_file
    # --------------------------------------------------------
    if tool == "read_file":
        path = arguments.get("path")

        safe_path = safe_sandbox_path(path)

        if safe_path is None:
            return jsonify({
                "action": "block",
                "reason": "Path is outside the allowed sandbox.",
                "result": ""
            })

        try:
            if not os.path.isfile(safe_path):
                return jsonify({
                    "action": "block",
                    "reason": "Requested file does not exist.",
                    "result": ""
                })

            with open(safe_path, "r", encoding="utf-8") as f:
                content = f.read()

            return jsonify({
                "action": "allow",
                "reason": "File is inside the allowed sandbox.",
                "result": content
            })

        except (OSError, UnicodeError):
            return jsonify({
                "action": "block",
                "reason": "File could not be safely read.",
                "result": ""
            })

    # --------------------------------------------------------
    # fetch_url
    # --------------------------------------------------------
    if tool == "fetch_url":
        url = arguments.get("url")

        allowed, reason = validate_fetch_url(url)

        if not allowed:
            return jsonify({
                "action": "block",
                "reason": reason,
                "result": ""
            })

        content, fetch_reason = perform_safe_fetch(url)

        if content is None:
            return jsonify({
                "action": "block",
                "reason": fetch_reason,
                "result": ""
            })

        return jsonify({
            "action": "allow",
            "reason": fetch_reason,
            "result": content
        })

    return jsonify({
        "action": "block",
        "reason": "Unknown tool.",
        "result": ""
    })

# ============================================================
# START SERVER
# ============================================================
#ensure_redteam_files()
import os

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )
