from flask import Flask, request, jsonify
from urllib.parse import urlparse
import os
import re
import shlex
import base64
# ============================================================
# Q4 - SKILL SAFETY AUDIT SCANNER
# ============================================================

import re
import json
from urllib.parse import urlparse


VALID_CATEGORIES = {
    "hardcoded_secret",
    "prompt_injection",
    "excessive_permissions",
    "unclear_provenance",
}


def get_skill_text(data):
    """
    The grader sends the skill markdown inside the 'skill' field.
    """

    if not isinstance(data, dict):
        return ""

    skill = data.get("skill", "")

    if isinstance(skill, str):
        return skill

    return ""


# ------------------------------------------------------------
# HARDCODED SECRET DETECTION
# ------------------------------------------------------------

def detect_hardcoded_secret(text):
    """
    Detect actual-looking credentials rather than generic words
    such as 'API key' or 'secret'.
    """

    # Strong credential formats

    strong_patterns = [

        # OpenAI-style keys
        r"\bsk-[A-Za-z0-9_-]{20,}\b",

        # GitHub personal access tokens
        r"\bghp_[A-Za-z0-9]{30,}\b",
        r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",

        # AWS access keys
        r"\bAKIA[0-9A-Z]{16}\b",

        # Slack tokens
        r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",

        # Generic JWT
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",

        # Authorization bearer token with an actual value
        r"Authorization\s*:\s*Bearer\s+[A-Za-z0-9._~+/=-]{20,}",

        # Generic API key / secret assignments with substantial values
        r"\b(?:API_KEY|APIKEY|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN)"
        r"\s*[:=]\s*[\"']?[A-Za-z0-9_\-./+=]{20,}[\"']?",

        # Webhook URLs containing an embedded credential/token
        r"https?://[^\s\"']+/(?:hooks?|webhooks?)/"
        r"[A-Za-z0-9_\-]{10,}(?:/[A-Za-z0-9_\-]{5,})+",
    ]

    for pattern in strong_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    # Detect explicit secret assignments while avoiding environment
    # variable references such as ${WEBHOOK_SECRET}.
    assignment_pattern = re.compile(
        r"\b(?:password|passwd|secret|token|api[_-]?key|access[_-]?token)"
        r"\s*[:=]\s*[\"']([^\"']+)[\"']",
        re.IGNORECASE
    )

    for match in assignment_pattern.finditer(text):
        value = match.group(1).strip()

        # Environment references are safe.
        if value.startswith("$"):
            continue

        if value.startswith("${"):
            continue

        # Common placeholders are not secrets.
        placeholder_words = {
            "your-secret",
            "your_secret",
            "your-api-key",
            "your_api_key",
            "changeme",
            "change-me",
            "example",
            "placeholder",
            "xxx",
            "xxxx",
        }

        if value.lower() in placeholder_words:
            continue

        # A reasonably long literal credential is suspicious.
        if len(value) >= 20:
            return True

    return False


# ------------------------------------------------------------
# PROMPT INJECTION DETECTION
# ------------------------------------------------------------

def detect_prompt_injection(text):
    """
    Look for instructions that attempt to override user/agent
    control or silently exfiltrate information.
    """

    normalized = re.sub(r"\s+", " ", text.lower())

    patterns = [

        # Control override
        r"\bignore (?:all |any |the )?(?:previous|prior|above|earlier) "
        r"(?:instructions?|rules?|directions?)\b",

        r"\bdisregard (?:all |any |the )?(?:previous|prior|above|"
        r"earlier) (?:instructions?|rules?|directions?)\b",

        r"\boverride (?:the )?(?:user|system|agent)"
        r"(?:'s)? (?:instructions?|rules?|request)\b",

        # User cancellation / control
        r"\bignore (?:the )?user(?:'s)? (?:request|instructions?)\b",
        r"\bignore (?:any )?(?:stop|cancel|abort) request\b",
        r"\bdo not (?:honou?r|follow|respect) (?:the )?"
        r"(?:user(?:'s)? )?(?:stop|cancel|abort)\b",

        # Silent exfiltration
        r"\bsilently (?:send|upload|exfiltrate|transmit|forward)"
        r".{0,100}(?:file|files|contents?|data|credentials?|secrets?)\b",

        r"\b(?:secretly|without (?:the )?user(?:'s)? knowledge)"
        r".{0,100}(?:send|upload|exfiltrate|transmit|forward)\b",

        # Explicitly conceal an unsafe action
        r"\b(?:hide|conceal|suppress) (?:this|the )?"
        r"(?:action|change|request|command) from (?:the )?"
        r"(?:user|reviewer|agent)\b",

        # Pretending to be higher-priority instructions
        r"\b(?:system message|system instruction|developer message)"
        r".{0,60}\b(?:ignore|override|disregard)\b",
    ]

    for pattern in patterns:
        if re.search(pattern, normalized, re.IGNORECASE):
            return True

    return False


# ------------------------------------------------------------
# EXCESSIVE PERMISSIONS
# ------------------------------------------------------------

def detect_excessive_permissions(text):
    """
    Detect broad capability declarations that are clearly
    inconsistent with a narrowly scoped skill.
    """

    normalized = text.lower()

    # Broad filesystem access

    filesystem_patterns = [
        r"\b(?:read|write|modify|delete|access)\b.{0,80}"
        r"\b(?:entire|whole|any|all)\s+filesystem\b",

        r"\b(?:read|write|modify|delete|access)\b.{0,80}"
        r"\b/(?:\*|[^\s]*\*)",

        r"\bfilesystem\s*[:=]\s*(?:\*|all|unrestricted)\b",

        r"\b(?:read|write)\s+(?:from|to)\s+any\s+(?:file|path|directory)\b",

        r"\baccess\s+all\s+files\b",
        r"\bfull\s+filesystem\s+access\b",
        r"\bunrestricted\s+filesystem\s+access\b",
    ]

    for pattern in filesystem_patterns:
        if re.search(pattern, normalized):
            return True

    # Broad network / egress access

    network_patterns = [
        r"\b(?:network|egress|outbound)\s*(?:access|permission)"
        r"\s*[:=]\s*(?:\*|all|any|unrestricted)\b",

        r"\b(?:connect|send|request|access)\b.{0,60}"
        r"\bany\s+(?:domain|host|website|internet)\b",

        r"\b(?:network|internet)\s+access\s+to\s+any\b",

        r"\bunrestricted\s+(?:network|internet|egress)\b",

        r"\ball\s+domains\b",
        r"\bany\s+domain\b",
        r"\bany\s+host\b",
    ]

    for pattern in network_patterns:
        if re.search(pattern, normalized):
            return True

    # Dangerous capability combinations explicitly declared
    # as permissions.

    capability_patterns = [
        r"\bpermissions?\s*:\s*.*\b(?:filesystem|network)\b"
        r".*\b(?:all|any|unrestricted|\*)\b",

        r"\b(?:allow|grant)\b.{0,30}"
        r"\b(?:read|write)\b.{0,30}"
        r"\b(?:all|any|entire|unrestricted)\b",
    ]

    for pattern in capability_patterns:
        if re.search(pattern, normalized):
            return True

    return False


# ------------------------------------------------------------
# PROVENANCE
# ------------------------------------------------------------

def has_frontmatter(text):
    stripped = text.lstrip()

    return (
        stripped.startswith("---")
        and "\n---" in stripped[3:]
    )


def detect_unclear_provenance(text):
    """
    A skill is considered provenance-unclear when it has no
    meaningful author/version/changelog metadata at all, or
    when it silently rewrites its own version metadata.
    """

    stripped = text.lstrip()

    frontmatter = ""

    if stripped.startswith("---"):
        parts = stripped.split("---", 2)

        if len(parts) >= 3:
            frontmatter = parts[1].lower()

    # Explicit silent self-modification of version metadata.
    silent_rewrite_patterns = [
        r"\bsilently\s+(?:update|change|rewrite|modify)"
        r".{0,100}\bversion\b",

        r"\bwithout\s+(?:surfacing|notifying|telling|showing)"
        r".{0,100}\bversion\b",

        r"\b(?:quietly|silently)\b.{0,100}"
        r"\b(?:changelog|change\s+log)\b",
    ]

    for pattern in silent_rewrite_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True

    # If there is frontmatter, inspect provenance fields.
    if frontmatter:
        has_author = bool(
            re.search(
                r"^\s*(?:author|authors|maintainer)\s*:",
                frontmatter,
                re.MULTILINE
            )
        )

        has_version = bool(
            re.search(
                r"^\s*version\s*:",
                frontmatter,
                re.MULTILINE
            )
        )

        has_changelog = bool(
            re.search(
                r"^\s*(?:changelog|change_log|changes)\s*:",
                frontmatter,
                re.MULTILINE
            )
        )

        # If none of the provenance fields exist, provenance is unclear.
        if not has_author and not has_version and not has_changelog:
            return True

    else:
        # No frontmatter and no recognizable provenance metadata.
        has_author = bool(
            re.search(r"\bauthor\s*:", text, re.IGNORECASE)
        )

        has_version = bool(
            re.search(r"\bversion\s*:", text, re.IGNORECASE)
        )

        has_changelog = bool(
            re.search(r"\b(?:changelog|change\s+log)\b", text, re.IGNORECASE)
        )

        if not has_author and not has_version and not has_changelog:
            return True

    return False


# ------------------------------------------------------------
# MAIN SCANNER
# ------------------------------------------------------------

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

    # Deterministic ordering
    return [
        category
        for category in [
            "hardcoded_secret",
            "prompt_injection",
            "excessive_permissions",
            "unclear_provenance",
        ]
        if category in categories
    ]


@app.route("/scan", methods=["POST"])
def scan_endpoint():

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"categories": []})

    skill = get_skill_text(data)

    categories = scan_skill(skill)

    return jsonify({
        "categories": categories
    })
    
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