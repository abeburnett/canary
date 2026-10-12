"""Plain-language text for what Canary found (program 2026-10-06, section 2).

Every string in this module is Canary's own: no package text and no model
text ever passes through it, so the headline and the steps are safe in an
agent's output and in the person's dialogs. Only `render` and `run` handle the
skill's own text (excerpts and file names), and they serve `canary explain`,
which refuses to run outside the person's terminal.
"""

import os
import secrets
import tarfile
import time

from canary import catalog, scan

# check_id -> (label, what it looks for, why it matters). A test keeps this in
# step with the catalog: a rule cannot ship without its text.
RULES = {
    "instruction-override": (
        "overriding the agent's instructions",
        "Phrases that tell the agent to ignore or replace its instructions, such as "
        "\"ignore previous instructions\".",
        "A skill that does this can take over the agent. Defensive skills sometimes quote "
        "these phrases to warn against them."),
    "identity-rewrite": (
        "giving the agent a new role",
        "Phrases such as \"you are now a…\" or \"adopt the persona of\".",
        "A new role can switch off the agent's usual care. Persona and role-play skills use "
        "these phrases on purpose."),
    "safeguard-bypass": (
        "skipping approvals or safety checks",
        "Phrases that tell the agent to skip confirmation, approvals, the sandbox or hooks.",
        "The agent could then act without asking you. Tool documentation sometimes describes "
        "such options without asking the agent to use them."),
    "exfiltration": (
        "sending data to an outside address",
        "Commands or instructions that send data to a web address, such as a curl upload or "
        "a chat webhook.",
        "This is how a skill could copy your files or secrets off this Mac. API documentation "
        "also shows upload commands, usually to the vendor's own address."),
    "shell-pipe": (
        "running a downloaded script",
        "A download piped straight into a shell, such as curl … | sh.",
        "The script runs without anyone reading it, and it can change after the check. "
        "Install guides often show this pattern."),
    "credential-access": (
        "reaching for passwords or keys",
        "SSH keys, cloud credentials, the keychain, .env files, or passwords together with "
        "reading or sending them.",
        "A skill that reads credentials can misuse or leak them. Setup guides mention these "
        "files when they explain configuration."),
    "persistence": (
        "staying on after the session",
        "Instructions to add launch agents, cron jobs or login items, or to edit agent "
        "settings or other skills.",
        "A skill that installs itself elsewhere keeps running after you remove it."),
    "stealth": (
        "hiding actions from you",
        "Phrases that tell the agent not to tell you what it does.",
        "Hiding actions takes away your chance to say no. Legitimate skills rarely need it."),
    "prompt-leak": (
        "revealing the agent's prompt",
        "Phrases that ask the agent to print its system prompt or instructions.",
        "A leaked prompt can expose private instructions. Prompt-writing guides discuss this "
        "as an attack to defend against."),
    "obfuscation": (
        "encoded text",
        "Long base64 text.",
        "Encoded text can hide instructions a reader cannot see. Embedded images and keys "
        "also look like this."),
    "invisible-character": (
        "invisible characters",
        "Zero-width, bidirectional or tag characters inside words.",
        "Invisible characters can hide instructions or change what a word means."),
    "mixed-script-word": (
        "look-alike letters",
        "Words that mix Latin letters with Cyrillic or Greek look-alikes.",
        "Look-alike letters can disguise a web address or command as a familiar one."),
    "external-url": (
        "web addresses",
        "Links to outside web pages.",
        "Recorded only: links alone never change the verdict."),
}

# A context label never changes a score; it only says where a finding sits.
CONTEXT = {
    "code_example": "Inside a code example. Examples are often documentation, but a skill can "
                    "still tell the agent to run them.",
    "forbidding": "On a line that warns against it. Skills sometimes quote a phrase to forbid "
                  "it; read the line to be sure.",
}
CONTEXT_TAG = {"code_example": "code example", "forbidding": "warns against it"}

ORDER = [c[0] for c in catalog.CHECKS] + list(catalog.EXTRA)

# The next step for each reason that keeps a verdict at NEEDS_REVIEW. Two
# families read differently inside an install dialog, where the person must
# choose Cancel before looking.
_STEPS = {
    "patterns": (
        "Look at the flagged lines: run canary explain with the same link or folder in your "
        "own terminal. Install it if they are only documentation; skip it if they tell the "
        "agent to do something you did not ask for.",
        "To look at the flagged lines first, choose Cancel, then run canary explain on the "
        "skill's GitHub link (for npx skills add owner/repo, that is "
        "https://github.com/owner/repo) or folder in your own terminal. Install it if they "
        "are only documentation; skip it if they tell the agent to do something you did not "
        "ask for."),
    "incomplete": (
        "Some files could not be read, so the check is incomplete. Install it only if you "
        "trust where it came from.",) * 2,
    "nothing": (
        "SkillCanary found no readable text in it, so there was nothing to check. Skip it "
        "unless you know why it is empty.",) * 2,
    "code": (
        "It runs code or grants tools, so it needs your approval whatever the scan found. "
        "Install it only if you trust where it came from.",) * 2,
    "unavailable": (
        "To add the AI review, sign in to Claude Code or set ANTHROPIC_API_KEY or "
        "OPENAI_API_KEY, then check it again.",) * 2,
    "too_large": (
        "The AI review reads only skills under 256 KB. Look at the flagged lines with canary "
        "explain, or install it only if you trust where it came from.",
        "The AI review reads only skills under 256 KB. To look at the flagged lines, choose "
        "Cancel and run canary explain on the skill's GitHub link or folder in your own "
        "terminal, or install it only if you trust where it came from."),
    "failed": (
        "Check it again. If the AI review keeps failing, decide from the pattern scan with "
        "canary explain.",
        "Try the install again. If the AI review keeps failing, choose Cancel and run canary "
        "explain on the skill's GitHub link or folder in your own terminal."),
    "review": (
        "The AI review wants a person to look. Run canary explain with the same link or "
        "folder in your own terminal to see what it noticed.",
        "The AI review wants a person to look. Choose Cancel and run canary explain on the "
        "skill's GitHub link or folder in your own terminal to see what it noticed."),
}


def _join(items):
    """a, a and b, a, b and c."""
    items = list(items)
    return items[0] if len(items) <= 1 else ", ".join(items[:-1]) + " and " + items[-1]


def scored_labels(check):
    """The labels of the checks with at least one scored finding, in catalog
    order (info findings are recorded, not scored)."""
    ids = {f["check_id"] for f in check["scan"]["findings"] if f["severity"] != "info"}
    return [RULES[i][0] for i in ORDER if i in ids]


# The headline's last resort. Dialogs that show a recommendation leave it out:
# it says nothing the recommendation does not.
GENERIC_HEADLINE = "This skill needs your judgment."


def headline(check, confident):
    """One sentence: the combined judgment of the scan and the AI review."""
    verdict, c, labels = check["verdict"], check["classifier"], scored_labels(check)
    if verdict == "UNSAFE" and c.get("verdict") == "UNSAFE":
        text = "SkillCanary judged this skill unsafe: the AI review found it unsafe."
        return text + (f" The pattern scan also found {_join(labels)}." if labels else "")
    if verdict == "UNSAFE":
        return f"SkillCanary judged this skill unsafe: the pattern scan found {_join(labels)}."
    if verdict == "LIKELY_SAFE":
        return "No problems found: the pattern scan and the AI review both passed it."
    scan_part = check["scan"]
    if (c.get("status") == "ok" and c.get("verdict") == "SAFE" and confident
            and scan_part["coverage"]["complete"]
            and not any(k["kind"] in scan.REVIEW_CAPABILITIES for k in scan_part["capabilities"])
            and scan_part["threat_verdict"] == "NEEDS_REVIEW"):
        return (f"The AI review judged this skill safe ({c['confidence']:.2f}). The pattern scan "
                f"flagged {_join(labels)} for you to look at.")
    return GENERIC_HEADLINE


def next_steps(check, confident, flow):
    """The steps for the reasons that keep the verdict at NEEDS_REVIEW, in
    reason order and without repeats; empty for any other verdict. `flow` is
    "check" (also canary add) or "install"."""
    if check["verdict"] != "NEEDS_REVIEW":
        return []
    which = 1 if flow == "install" else 0
    s, c = check["scan"], check["classifier"]
    families = []
    if s["threat_verdict"] != "LIKELY_SAFE":
        families.append("patterns")
    coverage = s["coverage"]
    if not coverage["complete"]:
        blocking = [x for x in coverage["skipped"] if x["reason"] != "media"]
        families.append("nothing" if coverage["files_scanned"] == 0 and not blocking
                        else "incomplete")
    if any(k["kind"] in scan.REVIEW_CAPABILITIES for k in s["capabilities"]):
        families.append("code")
    status = c.get("status")
    if status == "unavailable":
        families.append("unavailable")
    elif status == "too_large":
        families.append("too_large")
    elif status in ("failed", "invalid"):
        families.append("failed")
    elif status == "ok" and (c.get("verdict") == "NEEDS_REVIEW"
                             or (c.get("verdict") == "SAFE" and not confident)):
        families.append("review")
    return list(dict.fromkeys(_STEPS[f][which] for f in families))


# ---- What a finding means for you, and what to do (program 2026-10-12) -------

# check_id -> the risk in plain words, as one sentence about the skill. A test
# keeps this in step with RULES.
RISKS = {
    "instruction-override": "It tells the agent to ignore its instructions, which hands the "
                            "skill control of the agent.",
    "identity-rewrite": "It gives the agent a new role, which can switch off its usual care.",
    "safeguard-bypass": "It tells the agent to skip approvals or safety checks, so the agent "
                        "could act without asking you.",
    "exfiltration": "It can send your files or data to an outside web address.",
    "shell-pipe": "It runs a script downloaded from the internet that nobody has read.",
    "credential-access": "It can read your passwords or keys.",
    "persistence": "It can keep running after you remove it.",
    "stealth": "It tells the agent to hide what it does from you.",
    "prompt-leak": "It asks the agent to reveal its private instructions.",
    "obfuscation": "It holds encoded text that can hide instructions you cannot read.",
    "invisible-character": "It hides characters you cannot see inside its words.",
    "mixed-script-word": "It uses look-alike letters that can disguise a web address or "
                         "command.",
    "external-url": "It links to outside web pages.",
}

# (check_id, detail) -> a sharper sentence when the catalog knows what the
# pattern reaches for. A test keeps this equal to catalog.details().
DETAILS = {
    ("credential-access", "ssh"): "It can read your SSH keys (~/.ssh), which unlock your "
                                  "servers and code hosts.",
    ("credential-access", "cloud"): "It can read your cloud logins (AWS, Google Cloud, "
                                    "Kubernetes or Docker).",
    ("credential-access", "keychain"): "It can read passwords from your macOS keychain.",
    ("credential-access", "pem"): "It reaches for private key files (.pem).",
    ("credential-access", "env"): "It can read your .env files, which usually hold API keys.",
    ("credential-access", "secret-send"): "It can send a password, API key or token "
                                          "somewhere.",
    ("credential-access", "ask-secret"): "It asks you to type a password, passphrase or "
                                         "private key.",
    ("exfiltration", "chat-webhook"): "It can post your data to a Discord or Slack webhook.",
    ("exfiltration", "catcher"): "It can send your data to a throwaway collection address "
                                 "(webhook.site, ngrok and the like), a common sign of theft.",
    ("exfiltration", "upload"): "It can upload your files to a web address.",
    ("persistence", "schedule"): "It can set itself to run on its own (launch agent, cron "
                                 "or login item), even after you remove it.",
    ("persistence", "dotfiles"): "It can change your shell or SSH settings, so its changes "
                                 "outlive the session.",
    ("persistence", "agent-config"): "It can change your agent's settings, hooks or other "
                                     "skills.",
}

# The three things SkillCanary recommends. `text` is the sentence the person
# reads; `action` is for agents and scripts.
RECOMMEND = {
    "install": "Recommended: install. SkillCanary found nothing that needs your judgment.",
    "trust": "Recommended: install only if you trust its author. Nothing in it looks like an "
             "attack, but SkillCanary cannot vouch for it.",
    "decline": "Recommended: decline, unless you wrote it or know why it does this.",
}
# `trust` when the AI review did not run: the pattern scan alone passes most
# attacks (bench, 2026-10-12: 44 of 60 samples), so say so.
UNREVIEWED = ("Recommended: install only if you trust its author. The AI review did not run, "
              "and the pattern scan alone misses most attacks.")

# Attack checks: one open hit (not in a code example, not on a line that warns
# against it) without the AI review's confident pass means decline.
_ATTACKS = {cid for cid, _, sev, _, _, _ in catalog.CHECKS if sev == "high"} | {
    cid for cid, (_, sev, _) in catalog.EXTRA.items() if sev == "high"}


def risk(finding):
    """The plain sentence for one finding: Canary's own text only."""
    return DETAILS.get((finding["check_id"], finding.get("detail")), RISKS[finding["check_id"]])


def _scored(findings):
    return [f for f in findings if f["severity"] != "info"]


def risks(check):
    """The plain sentences for the scored findings, without repeats, in
    catalog order."""
    found = _scored(check["scan"]["findings"])
    found.sort(key=lambda f: ORDER.index(f["check_id"]))
    return list(dict.fromkeys(risk(f) for f in found))


def _vouched(check, confident):
    c = check["classifier"]
    return c.get("status") == "ok" and c.get("verdict") == "SAFE" and confident


def recommend(check, confident):
    """{"action": install | trust | decline, "text": …}. UNSAFE is decline and
    LIKELY_SAFE is install. NEEDS_REVIEW is decline when an attack pattern sits
    in plain instructions and the AI review did not confidently pass it, and
    trust otherwise (examples, warnings, code, an incomplete or missing
    review)."""
    verdict = check["verdict"]
    if verdict == "UNSAFE":
        action = "decline"
    elif verdict == "LIKELY_SAFE":
        action = "install"
    else:
        open_attack = any(f["check_id"] in _ATTACKS and f["context"] is None
                          for f in _scored(check["scan"]["findings"]))
        action = "decline" if open_attack and not _vouched(check, confident) else "trust"
    if action == "trust" and check["classifier"].get("status") != "ok":
        return {"action": action, "text": UNREVIEWED}
    return {"action": action, "text": RECOMMEND[action]}


WORST_ACTION = {"install": 0, "trust": 1, "decline": 2}

_DIALOG_TAG = {"code_example": "in a code example", "forbidding": "on a line that warns against it"}


def evidence_lines(snapshot, limit=5, per_risk=2):
    """For the person's dialog only (owner decision 2026-10-12): each risk,
    then up to `per_risk` lines of the skill's own text that raised it, as
    `<file> line <n>: "<text>"`. The quoted text and file names come from the
    package, so the dialog labels them, and none of this reaches an agent.
    Empty when the snapshot cannot be read."""
    try:
        result = scan.scan_package(snapshot, excerpts=True)
    except (OSError, ValueError, scan.PathError):
        return []
    found = _scored(result["findings"])
    found.sort(key=lambda f: (ORDER.index(f["check_id"]), f["path"], f["line"]))
    groups = {}
    for f in found:
        groups.setdefault(risk(f), []).append(f)
    lines = []
    for n, (sentence, hits) in enumerate(groups.items()):
        if n == limit:
            lines.append(f"- and {len(groups) - limit} more; canary explain shows them all.")
            break
        lines.append(f"- {sentence}")
        for f in hits[:per_risk]:
            text = scan.terminal_safe(" ".join(f["excerpt"].split()))
            if len(text) > 120:
                text = text[:117] + "..."
            tag = f" ({_DIALOG_TAG[f['context']]})" if f.get("context") else ""
            lines.append(f"    {scan.terminal_safe(f['path'])} line {f['line']}{tag}: \"{text}\"")
        if len(hits) > per_risk:
            lines.append(f"    and {len(hits) - per_risk} more lines like this")
    return lines


# ---- `canary explain`: the skill's own text, for the person's terminal -------

def _bullets(lines):
    return [f"- {line}" for line in lines]


def render(result):
    """The layout `canary explain` prints, from a `classify.check(...,
    excerpts=True)` result. It holds the skill's own text."""
    sections = [[f"Verdict: {result['verdict']}", result["headline"],
                 result["recommendation"]["text"]]]
    findings = [f for f in result["scan"]["findings"] if f["severity"] != "info"]
    for check_id in ORDER:
        mine = [f for f in findings if f["check_id"] == check_id]
        if not mine:
            continue
        label, looks_for, why = RULES[check_id]
        lines = [label, f"  What it looks for: {looks_for}", f"  Why it matters: {why}"]
        for f in mine:
            lines.append(f"  {scan.terminal_safe(f['path'])}:{f['line']}  {f['excerpt']!r}")
            if f.get("context"):
                lines.append(f"    {CONTEXT[f['context']]}")
            lines.append(f"    {risk(f)}")
        sections.append(lines)
    from canary import add
    can = sorted({add.PLAIN[k["kind"]] for k in result["scan"]["capabilities"]
                  if k["kind"] in add.PLAIN})
    if can:
        sections.append(["What it can do:"] + _bullets(f"It {c}." for c in can))
    skipped = result["scan"]["coverage"]["skipped"]
    if skipped:
        sections.append(["Not read:"] + _bullets(f"{scan.terminal_safe(s['path'])} ({s['reason']})" for s in skipped))
    c = result["classifier"]
    review = f"AI review: {c['status']}"
    if c["status"] == "ok":
        review += f", said {c['verdict']} at confidence {c['confidence']:.2f}"
    lines = [review]
    for f in c["findings"]:
        lines.append(f"  [{f['severity'].upper():6}] {f['category']}"
                     + (f"  {f['evidence']!r}: {scan.terminal_safe(f['reasoning'])}"
                    if "evidence" in f else ""))
    if "summary" in c:
        lines.append(f"  Summary: {scan.terminal_safe(c['summary'])}")
    sections.append(lines)
    if result["next_steps"]:
        sections.append(["What you can do:"] + _bullets(result["next_steps"]))
    return "\n\n".join("\n".join(lines) for lines in sections)


def run(source, *, support_dir=None, fetch=None, backend="auto", model=None, timeout_s=None):
    """Check a GitHub link or a local folder with excerpts. A link is fetched
    and extracted by `canary add`'s own code into a private folder under the
    support folder, which is removed afterwards; a folder is checked in place.
    Raises add.SourceError or scan.PathError."""
    from canary import add, classify
    timeout_s = timeout_s or classify.DEFAULT_TIMEOUT_S
    support_dir = support_dir or add.SUPPORT_DIR
    log_dir = os.path.join(support_dir, "logs")
    kind, *rest = add.parse_source(source)
    if kind == "local":
        return classify.check(rest[0], backend=backend, model=model, timeout_s=timeout_s,
                              log_dir=log_dir, excerpts=True)
    run_id = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4)
    run_dir = os.path.join(support_dir, "quarantine", f"explain-{run_id}")
    os.makedirs(run_dir, mode=0o700)
    work = os.path.join(run_dir, "work")
    os.mkdir(work, 0o700)
    try:
        try:
            snapshot = add._unpack("github", rest, fetch or add.github_fetch, work, run_dir)[0]
        except (OSError, ValueError, UnicodeError, tarfile.TarError):
            # Error text from the file system can quote package file names.
            raise add.SourceError("The package could not be unpacked safely.") from None
        return classify.check(snapshot, backend=backend, model=model, timeout_s=timeout_s,
                              log_dir=log_dir, excerpts=True)
    finally:
        add._remove(run_dir)
