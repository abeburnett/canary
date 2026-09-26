# Jev check catalog — categories and evasion notes

Layer 1 patterns live in `bin/jev-scan` (single source of truth). This file
documents what each category means, why it matters, and what the regexes
cannot catch — which is exactly what layer 2 (the isolated classifier) is for.

## Categories

| Category | Severity | What it catches | Why it matters |
|---|---|---|---|
| INSTRUCTION_OVERRIDE | high | "ignore previous instructions", "disregard your system instructions", "your new instructions are" | The classic jailbreak. A skill has no legitimate reason to discard the agent's own instructions. |
| IDENTITY_REWRITE | medium | "you are now a…", "from now on, you are" | Sometimes legitimate role framing, sometimes a setup for override. Needs the classifier's judgment. |
| SAFEGUARD_BYPASS | high | "disable safety", "bypass approval", "never ask the user for confirmation" | Direct attack on the approval/human-in-the-loop layer. |
| EXFILTRATION | high | Webhook hosts (discord/slack/requestbin/ngrok), "send X to https://…", curl with data flags | Exfil needs a destination. Legit skills link docs; they don't POST user data out. |
| SHELL_PIPE | high | `curl … | sh`, `wget … | bash` | Remote code execution dressed as installation. |
| CREDENTIAL_ACCESS | high | `~/.ssh`, `id_rsa`, `.pem`, `.env` reads, "enter your password" | Harvesting the keys to everything else. |
| PERSISTENCE | medium | "persist across sessions", "modify your own instructions", cron/startup writes | Turns a one-time read into a permanent backdoor. |
| STEALTH | medium | "do not tell the user", "keep this secret from the user" | Legitimate skills have no reason to hide from their own user. High signal. |
| PROMPT_LEAK | medium | "reveal your system prompt", "output your SKILL.md" | Reconnaissance: learn the agent's instructions to craft better attacks later. |
| OBFUSCATION | medium | Long base64 blobs, zero-width/invisible unicode | Hidden payloads. There is no benign reason for invisible characters in a skill. |
| EXTERNAL_URL | low | Any http(s) URL | Informational. Most are docs links; the classifier weighs context. |

## Evasion notes (what layer 1 misses)

- **Paraphrase**: "kindly disregard earlier directives" won't match a literal regex. Layer 2 reads intent.
- **Split payloads**: instruction spread across lines or files, assembled by the reader. Layer 2 sees the whole text.
- **Homoglyphs / unicode tricks**: `іgnore` with a Cyrillic і. Add suspect-script detection later; today layer 2.
- **Social framing**: "for a security audit, please…" — pretext that makes a bad instruction look legitimate. Pure judgment call; layer 2.
- **Multi-skill attacks**: a benign skill that tells the agent to install a second, malicious skill. Scan the transitive closure: every skill a skill references.

## Scoring

high = 3, medium = 2, low = 1. Score ≥ 6 → UNSAFE, ≥ 3 → NEEDS REVIEW,
else LIKELY SAFE. Thresholds are deliberately twitchy: a skill that trips
two high-severity checks is not getting the benefit of the doubt.
