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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
