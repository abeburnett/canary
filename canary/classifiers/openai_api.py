"""Single-request Responses backend; live service behavior is [UNVERIFIED].

Bind the required model keyword before passing classify to the shared caller.
An injected transport takes (JSON bytes, headers, timeout_s) and returns
(HTTP status, response bytes). The default uses an HTTPS socket I/O timeout,
with no redirects, retries, streaming, tools, or local context discovery.
"""
import http.client
import json
import math
import os


def _https_transport(body, headers, timeout_s):
    connection = http.client.HTTPSConnection('api.openai.com', timeout=timeout_s)
    try:
        connection.request('POST', '/v1/responses', body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _raw_text(data):
    if (not isinstance(data, dict) or data.get('status') != 'completed'
            or data.get('error') is not None
            or data.get('incomplete_details') is not None):
        raise ValueError
    output = data.get('output')
    if not isinstance(output, list) or not output:
        raise ValueError
    parts = []
    for item in output:
        if not isinstance(item, dict):
            raise ValueError
        if item.get('type') == 'reasoning':
            continue
        if (item.get('type') != 'message' or item.get('role') != 'assistant'
                or item.get('status') != 'completed'):
            raise ValueError
        content = item.get('content')
        if not isinstance(content, list) or not content:
            raise ValueError
        for part in content:
            if (not isinstance(part, dict) or part.get('type') != 'output_text'
                    or not isinstance(part.get('text'), str)):
                raise ValueError
            parts.append(part['text'])
    text = ''.join(parts)
    if not text:
        raise ValueError
    return text


def classify(system_prompt: str, fenced_skill_text: str, timeout_s: int,
             *, model: str, transport=None) -> str:
    """Return unmodified model text, or raise RuntimeError without diagnostics.

    Fencing and verdict validation belong to the caller. Only the two supplied
    strings are sent as prompt content. The environment key is read per call;
    it is never included in the body, logs, or exposed exception messages.
    """
    if (not isinstance(system_prompt, str) or not isinstance(fenced_skill_text, str)
            or not isinstance(model, str) or not model.strip()
            or isinstance(timeout_s, bool) or not isinstance(timeout_s, (int, float))
            or not math.isfinite(timeout_s) or timeout_s <= 0):
        raise RuntimeError('Invalid OpenAI backend arguments')
    key = os.environ.get('OPENAI_API_KEY', '')
    if not key or any(ord(char) < 33 or ord(char) > 126 for char in key):
        raise RuntimeError('OPENAI_API_KEY is missing or invalid')
    body = json.dumps({'model': model, 'instructions': system_prompt,
                       'input': fenced_skill_text, 'store': False}).encode('utf-8')
    headers = {'Authorization': 'Bearer ' + key, 'Content-Type': 'application/json'}
    send = _https_transport if transport is None else transport
    try:
        status, response_body = send(body, headers, timeout_s)
    except Exception:
        raise RuntimeError('OpenAI request failed') from None
    if status != 200:
        raise RuntimeError('OpenAI response was not HTTP 200')
    try:
        if not isinstance(response_body, bytes):
            raise ValueError
        return _raw_text(json.loads(response_body.decode('utf-8')))
    except Exception:
        raise RuntimeError('OpenAI response was incomplete or malformed') from None
