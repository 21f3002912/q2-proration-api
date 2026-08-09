from flask import Flask, request, jsonify
from urllib.parse import urlparse
import os
import re
import shlex
import base64

app = Flask(__name__)

# ============================================================
# Q2 - PRORATION ENDPOINT
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
# Q3 - AGENT HARNESS GUARDRAIL
# ============================================================

WORKSPACE = "/home/agent/workspace"
HOME = "/home/agent"
SECRET = "/home/agent/.env"
OUTBOX = "/data/agent/outbox"

ALLOWED_HOSTS = {
    "registry.npmjs.org",
    "api.github.com"
}


# ------------------------------------------------------------
# PATH NORMALIZATION
# ------------------------------------------------------------

def normalize_path(path, cwd=WORKSPACE):
    """
    Expand ~ and known environment variables, then normalize
    the path relative to the agent's working directory.
    """

    if not isinstance(path, str):
        return None

    path = path.strip()

    # Environment variable expansion
    path = re.sub(
        r"\$\{HOME\}",
        HOME,
        path
    )

    path = re.sub(
        r"\$HOME\b",
        HOME,
        path
    )

    path = re.sub(
        r"\$\{PWD\}",
        cwd,
        path
    )

    path = re.sub(
        r"\$PWD\b",
        cwd,
        path
    )

    # Tilde expansion
    if path == "~":
        path = HOME
    elif path.startswith("~/"):
        path = HOME + path[1:]

    # Normalize relative paths against agent workspace
    if not os.path.isabs(path):
        path = os.path.join(cwd, path)

    return os.path.normpath(path)


def is_secret_path(path, cwd=WORKSPACE):
    normalized = normalize_path(path, cwd)
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


# ------------------------------------------------------------
# BASE64 / SHELL OBFUSCATION
# ------------------------------------------------------------

def decode_base64_strings(command):
    """
    Find strings that look like base64 and decode them.
    This catches examples such as:

        echo Y2F0IC9ob21lL2FnZW50Ly5lbnY= | base64 -d | bash

    which decodes to:

        cat /home/agent/.env
    """

    decoded_commands = []

    candidates = re.findall(
        r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{12,}={0,2}(?![A-Za-z0-9+/])",
        command
    )

    for candidate in candidates:
        try:
            decoded = base64.b64decode(
                candidate,
                validate=True
            ).decode("utf-8", errors="ignore")

            if decoded:
                decoded_commands.append(decoded)

        except Exception:
            pass

    return decoded_commands


# ------------------------------------------------------------
# SECRET READ DETECTION
# ------------------------------------------------------------

def contains_secret_reference(command):
    """
    Detect direct and common obfuscated attempts to access
    /home/agent/.env.
    """

    if not isinstance(command, str):
        return False

    commands_to_check = [command]

    # Recursively inspect base64-decoded content
    for _ in range(3):
        new_commands = []

        for cmd in commands_to_check:
            new_commands.extend(decode_base64_strings(cmd))

        if not new_commands:
            break

        commands_to_check.extend(new_commands)

    # Check every representation
    for cmd in commands_to_check:

        # Environment expansion
        expanded = re.sub(r"\$\{HOME\}", HOME, cmd)
        expanded = re.sub(r"\$HOME\b", HOME, expanded)

        # Tilde expansion
        expanded = re.sub(
            r"(?<![\w/])~/",
            HOME + "/",
            expanded
        )

        # Direct absolute secret path
        if SECRET in expanded:
            return True

        # Token/path analysis
        try:
            tokens = shlex.split(expanded)
        except Exception:
            tokens = expanded.split()

        for token in tokens:

            # Remove shell punctuation
            cleaned = token.strip(
                "\"'`()[]{};,|&<>"
            )

            # Check normalized path
            if is_secret_path(cleaned):
                return True

            # Handle paths containing shell prefixes
            if SECRET in cleaned:
                return True

        # Detect common path construction patterns
        normalized_command = expanded.replace("\\", "/")

        if re.search(
            r"(?:^|[\s'\"`(])(?:cat|less|more|head|tail|grep|sed|awk|"
            r"cut|strings|base64|cp|tar|python|python3|perl|ruby|"
            r"php)\b.*(?:/home/agent/\.env|~/?\.env|\$HOME/?\.env)",
            normalized_command,
            re.IGNORECASE
        ):
            return True

    return False


# ------------------------------------------------------------
# BASH WRITE DETECTION
# ------------------------------------------------------------

def extract_bash_write_paths(command):
    """
    Detect common shell operations that write to a file.
    """

    paths = []

    try:
        tokens = shlex.split(command)
    except Exception:
        tokens = command.split()

    # Redirection:
    # echo hello > file
    # echo hello >> file
    for match in re.finditer(
        r"(?:^|\s)(?:>>|>)\s*([^\s;&|]+)",
        command
    ):
        paths.append(match.group(1))

    # tee file
    for i, token in enumerate(tokens):
        if token in ("tee", "tee-a", "tee-a"):
            if i + 1 < len(tokens):
                paths.append(tokens[i + 1])

        elif token == "tee" and i + 1 < len(tokens):
            next_token = tokens[i + 1]
            if next_token == "-a" and i + 2 < len(tokens):
                paths.append(tokens[i + 2])
            else:
                paths.append(next_token)

    # touch file
    for i, token in enumerate(tokens):
        if token == "touch":
            for candidate in tokens[i + 1:]:
                if not candidate.startswith("-"):
                    paths.append(candidate)

    # mkdir directory
    for i, token in enumerate(tokens):
        if token == "mkdir":
            for candidate in tokens[i + 1:]:
                if not candidate.startswith("-"):
                    paths.append(candidate)

    return paths


def bash_writes_outside_outbox(command):
    paths = extract_bash_write_paths(command)

    for path in paths:
        if not is_inside_outbox(path):
            return True

    return False


# ------------------------------------------------------------
# HTTP HOST VALIDATION
# ------------------------------------------------------------

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

        # EXACT hostname comparison.
        # This deliberately rejects:
        # registry.npmjs.org.evil.com
        # evil.registry.npmjs.org
        # api.github.com.evil.com
        return hostname in ALLOWED_HOSTS

    except Exception:
        return False


# ------------------------------------------------------------
# TOOL POLICY
# ------------------------------------------------------------

def evaluate_tool_call(data):

    if not isinstance(data, dict):
        return "block", "Invalid tool call."

    tool = data.get("tool")

    # ========================================================
    # BASH
    # ========================================================

    if tool == "bash":

        command = data.get("command")

        if not isinstance(command, str):
            return "block", "A bash command is required."

        # Never allow reading the secret.
        if contains_secret_reference(command):
            return (
                "block",
                "Reading /home/agent/.env is never permitted."
            )

        # Writes must stay inside outbox.
        if bash_writes_outside_outbox(command):
            return (
                "block",
                "Bash writes are permitted only inside /data/agent/outbox/."
            )

        return (
            "allow",
            "The bash command does not violate the restricted file policy."
        )

    # ========================================================
    # WRITE FILE
    # ========================================================

    elif tool == "write_file":

        path = data.get("path")

        if not isinstance(path, str):
            return "block", "A file path is required."

        normalized = normalize_path(path)

        if normalized == SECRET:
            return (
                "block",
                "Writing /home/agent/.env is outside the permitted write boundary."
            )

        if not is_inside_outbox(path):
            return (
                "block",
                "Files may only be written inside /data/agent/outbox/."
            )

        return (
            "allow",
            "The file is inside the permitted outbox directory."
        )

    # ========================================================
    # HTTP REQUEST
    # ========================================================

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

    # ========================================================
    # UNKNOWN TOOL
    # ========================================================

    return "block", "Unknown tool is not permitted."


# ============================================================
# GUARDRAIL ENDPOINT
# ============================================================

@app.route("/guardrail", methods=["POST"])
def guardrail():

    data = request.get_json(silent=True)

    decision, reason = evaluate_tool_call(data)

    return jsonify({
        "decision": decision,
        "reason": reason
    })


# ============================================================
# LOCAL SERVER
# ============================================================

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)