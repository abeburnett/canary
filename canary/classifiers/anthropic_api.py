"""Single-request Messages API backend on the person's own key.

An injected transport takes (JSON bytes, headers, timeout_s) and returns
(HTTP status, response bytes). The default makes one HTTPS request with no
redirects, retries, streaming or tools. Live service behavior is [UNVERIFIED].
"""
import http.client
import json
import math
import os


def _https_transport(body, headers, timeout_s):
    connection = http.client.HTTPSConnection("api.anthropic.com", timeout=timeout_s)
    try:
        connection.request("POST", "/v1/messages", body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _text(data):
    if not isinstance(data, dict) or data.get("stop_reason") != "end_turn":
        raise ValueError
    content = data.get("content")
    if not isinstance(content, list) or not content:
        raise ValueError
    parts = []
    for block in content:
        if not isinstance(block, dict) or block.get("type") != "text" \
                or not isinstance(block.get("text"), str):
            raise ValueError
        parts.append(block["text"])
    text = "".join(parts)
    if not text:
        raise ValueError
    return text


def classify(system_prompt: str, fenced_skill_text: str, timeout_s: int,
             *, model: str, transport=None) -> str:
    """Return unmodified model text, or raise RuntimeError without diagnostics.
    The key is read per call and never appears in the body or in errors."""
    if (not isinstance(system_prompt, str) or not isinstance(fenced_skill_text, str)
            or not isinstance(model, str) or not model.strip()
            or isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s) or timeout_s <= 0):
        raise RuntimeError("Invalid Anthropic backend arguments")
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key or any(ord(char) < 33 or ord(char) > 126 for char in key):
        raise RuntimeError("ANTHROPIC_API_KEY is missing or invalid")
    body = json.dumps({"model": model, "max_tokens": 4096, "system": system_prompt,
                       "messages": [{"role": "user", "content": fenced_skill_text}]}).encode("utf-8")
    headers = {"x-api-key": key, "anthropic-version": "2023-06-01",
               "content-type": "application/json"}
    send = _https_transport if transport is None else transport
    try:
        status, response_body = send(body, headers, timeout_s)
    except Exception:
        raise RuntimeError("Anthropic request failed") from None
    if status != 200:
        raise RuntimeError("Anthropic response was not HTTP 200")
    try:
        if not isinstance(response_body, bytes):
            raise ValueError
        return _text(json.loads(response_body.decode("utf-8")))
    except Exception:
        raise RuntimeError("Anthropic response was incomplete or malformed") from None
