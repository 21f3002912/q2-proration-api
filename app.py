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
# START SERVER
# ============================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)