"""Layer-1 threat pattern catalog: the single source of truth for patterns.

Every pattern is matched case-insensitively against normalized text
(scan.normalize). A pattern marked `doc` is documentation-shaped, and only
those can be dampened by a documentation context on the same line; attack
patterns are never dampened. External URLs are recorded but never scored:
a destination only matters when an instruction sends data to it, and the
EXFILTRATION patterns catch that.
"""

import re

# Documentation contexts: placeholders, CLI-flag docs, examples, env-var names.
DOC_CONTEXT = re.compile(
    r"<redacted>|--yes\b|(?:^|\s)-y\b|\be\.g\.|\bfor example\b|\bexample:"
    r"|\b[a-z][a-z0-9_]*(api[_-]?key|webhook_secret)\b",
    re.IGNORECASE)

# (check_id, category, severity, description, paragraph_pass, [(regex, doc), ...])
CHECKS = [
    ("instruction-override", "INSTRUCTION_OVERRIDE", "high",
     "Tries to override or discard the agent's own instructions", True,
     [(r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|earlier|above)\s+(instructions|directions|rules)", False),
      (r"disregard\s+(your\s+|all\s+|the\s+)?(system\s+|prior\s+|previous\s+|earlier\s+)?(instructions|directives|rules)", False),
      (r"override\s+your\s+(instructions|rules|guidelines)", False),
      (r"forget\s+(your|all|previous)\s+(instructions|rules)", False),
      (r"your\s+new\s+instructions\s+are", False),
      (r"previous\s+instructions\s+(no\s+longer|do\s+not)\s+apply", False)]),
    ("identity-rewrite", "IDENTITY_REWRITE", "medium",
     "Attempts to reassign the agent's identity or role mid-skill", True,
     [(r"you\s+are\s+now\s+(a|an|the)\s+\w+", False),
      (r"from\s+now\s+on,?\s+you\s+are", False),
      (r"adopt\s+the\s+persona\s+of", False)]),
    ("safeguard-bypass", "SAFEGUARD_BYPASS", "high",
     "Tells the agent to skip approvals, safety checks, or confirmation", True,
     [(r"disable\s+(the\s+)?(safety|guardrails|approvals|checks|sandbox|hooks)", False),
      (r"bypass\s+(the\s+)?(approval|permission|sandbox|safety)", False),
      (r"skip\s+(the\s+)?(approval|confirmation|safety)(\s+(step|check|process))?", False),
      (r"never\s+ask\s+(the\s+user\s+)?(for\s+)?(confirmation|permission|approval)", False),
      (r"do\s+not\s+ask\s+(the\s+user\s+)?(for\s+)?(confirmation|permission|approval)", False),
      (r"disableallhooks|dangerously-skip-permissions|bypasspermissions", False)]),
    ("exfiltration", "EXFILTRATION", "high",
     "Instructs the agent to send data to an external endpoint", True,
     [(r"discord(app)?\.com/api/webhooks", False),
      (r"hooks\.slack\.com/services", False),
      (r"requestbin\.(com|net)|requestcatcher\.com|webhook\.site|pipedream\.net|interact\.sh", False),
      (r"[a-z0-9-]+\.ngrok(-free)?\.(io|app|dev)", False),
      (r"(send|post|upload|forward|exfiltrate|transmit)\s+.{0,60}?\s+to\s+https?://", False),
      (r"curl\s+[^\n]*(-d\b|--data|--data-binary|-F\b|--form|-T\b|--upload-file)", False)]),
    ("shell-pipe", "SHELL_PIPE", "high",
     "Runs a remote download straight in a shell or interpreter", False,
     [(r"(curl|wget|iwr|invoke-webrequest)\b[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|fish|dash|ksh|python\d?|node|perl|ruby|iex)\b", False),
      (r"\b(sh|bash|zsh|source|\.)\s+<\(\s*(curl|wget)", False),
      (r"\$\(\s*(curl|wget)\b", False),
      (r"\beval\s+[\"']?\$\(", False)]),
    ("credential-access", "CREDENTIAL_ACCESS", "high",
     "Reaches for secrets, keys, or credentials on the machine", False,
     [(r"~/\.ssh|/\.ssh/|\bid_(rsa|ed25519|ecdsa|dsa)\b", False),
      (r"~/\.aws|aws_secret_access_key|~/\.config/gcloud|~/\.kube/config|~/\.netrc|~/\.docker/config\.json", False),
      (r"(keychain|security\s+find-(generic|internet)-password|login\.keychain)", False),
      (r"\.pem\b", True),
      (r"\.env\b.*(read|load|cat|send|upload)", True),
      (r"(api[_-]?key|secret[_-]?key|auth[_-]?token|password).{0,30}(send|post|upload|exfiltrate)", True),
      (r"(enter|paste|type)\s+(your|the)\s+(password|passphrase|seed\s+phrase|private\s+key)", False)]),
    ("persistence", "PERSISTENCE", "medium",
     "Tries to persist itself, escalate, or modify agent configuration", True,
     [(r"persist\s+across\s+sessions", False),
      (r"modify\s+your\s+own\s+instructions", False),
      (r"add\s+(yourself|a|an)\s+(cron|scheduled|launch\s*agent|login\s+item)", False),
      (r"run\s+on\s+(startup|login|boot)", False),
      (r"write\s+to\s+~/\.(config|ssh|aws|zshrc|bashrc|profile)", False),
      (r"(~/\.claude|~/\.codex|~/\.cursor|~/\.agents)/(settings[\w.]*\.json|hooks\.json|config\.toml|skills)", False),
      (r"launchctl\s+(load|bootstrap|bootout|unload)|LaunchAgents/|crontab\s", False)]),
    ("stealth", "STEALTH", "medium",
     "Instructs the agent to hide behavior from the user", True,
     [(r"do\s+not\s+(tell|inform|mention\s+(this\s+)?to)\s+the\s+user", False),
      (r"don'?t\s+(tell|mention\s+(this\s+)?to)\s+the\s+user", False),
      (r"keep\s+this\s+(secret|hidden)\s+from\s+the\s+user", False),
      (r"hide\s+.{0,30}\s+from\s+the\s+user", False),
      (r"without\s+(the\s+user|anyone)\s+(knowing|noticing)", False)]),
    ("prompt-leak", "PROMPT_LEAK", "medium",
     "Tries to get the agent to reveal its own prompt or instructions", True,
     [(r"reveal\s+your\s+(system\s+)?prompt", False),
      (r"print\s+your\s+(system\s+)?(prompt|instructions)", False),
      (r"output\s+your\s+(skill\.md|system\s+prompt|instructions)", False),
      (r"show\s+me\s+your\s+(system\s+)?prompt", False)]),
    ("obfuscation", "OBFUSCATION", "medium",
     "Obfuscated payload: long base64 blob", False,
     [(r"[A-Za-z0-9+/]{120,}={0,2}", False)]),
    ("external-url", "EXTERNAL_URL", "info",
     "External URL (recorded, not scored)", False,
     [(r"https?://[^\s)\"'>]+", False)]),
]

EXTRA = {
    "invisible-character": ("OBFUSCATION", "medium",
                            "Invisible or bidirectional-control character in text"),
    "mixed-script-word": ("OBFUSCATION", "medium",
                          "Word mixes Latin with Cyrillic or Greek look-alike letters"),
}

_COMPILED = [(cid, cat, sev, desc, para, [(re.compile(p, re.IGNORECASE), doc) for p, doc in pats])
             for cid, cat, sev, desc, para, pats in CHECKS]


def finding(check_id, path, line, excerpt, severity=None):
    if check_id in EXTRA:
        category, sev, desc = EXTRA[check_id]
    else:
        _, category, sev, desc, _, _ = next(c for c in CHECKS if c[0] == check_id)
    return {"check_id": check_id, "category": category, "severity": severity or sev,
            "description": desc, "path": path, "line": line, "excerpt": _clip(excerpt)}


def _clip(text):
    text = text.strip()
    return text if len(text) <= 160 else text[:157] + "..."


def match_line(path, line_no, line, raw_line):
    out = []
    doc_context = DOC_CONTEXT.search(line) is not None
    for cid, _, sev, _, _, patterns in _COMPILED:
        for rx, doc in patterns:
            if rx.search(line):
                severity = "info" if (doc and doc_context) else None
                out.append(finding(cid, path, line_no, raw_line, severity))
                break
    return out


def match_paragraph(path, start_line, joined, raw_joined):
    out = []
    for cid, _, _, _, para, patterns in _COMPILED:
        if not para:
            continue
        for rx, doc in patterns:
            if not doc and rx.search(joined):
                out.append(finding(cid, path, start_line, raw_joined))
                break
    return out
