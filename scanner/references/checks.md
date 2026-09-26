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
| SHELL_PIPE | high | `curl … \| sh`, `wget … \| bash` | Remote code execution dressed as installation. |
| CREDENTIAL_ACCESS | high | `~/.ssh`, `id_rsa`, `.pem`, `.env` reads, "enter your password" | Harvesting the keys to everything else. |
| PERSISTENCE | medium | "persist across sessions", "modify your own instructions", cron/startup writes | Turns a one-time read into a permanent backdoor. |
| STEALTH | medium | "do not tell the user", "keep this secret from the user" | Legitimate skills have no reason to hide from their own user. High signal. |
| PROMPT_LEAK | medium | "reveal your system prompt", "output your SKILL.md" | Reconnaissance: learn the agent's instructions to craft better attacks later. |
| OBFUSCATION | medium | Long base64 blobs, zero-width/invisible unicode | Hidden payloads. There is no benign reason for invisible characters in a skill. |
| EXTERNAL_URL | low | Any http(s) URL | Informational. Most are docs links; the classifier weighs context. |

## Calibration (2026-09-26)

Measured on 1,153 real-world skill files. Before → after:

- LIKELY_SAFE 890 → 987, NEEDS_REVIEW 140 → 153, UNSAFE 123 → 13
- 169 verdicts moved down; the planted-nasty fixture still scores 33/UNSAFE
  (detection of real attacks is unchanged).
- The 13 remaining UNSAFEs were individually characterized: 12 are official
  vendor skills documenting their own API keys, install commands, or API curl
  examples (Resend, Vercel, RevenueCat, Cloudflare Turnstile); 1
  (`hermes-agent`) is a remote-script-pipe install that needs publisher-trust
  verification, not a pattern fix. Zero genuine threats.

Three dampening rules keep documentation from scoring. Dampened findings are
recorded with severity `info` (weight 0) — still visible in the report, still
seen by layer 2, just not scored:

1. **URL volume** — only the first 5 EXTERNAL_URL findings per file score;
   links to known vendor doc hosts (anthropic.com, vercel.com, cloudflare.com,
   stripe.com, atlassian.com, github.com, microsoft.com, google dev domains)
   never score. Real exfiltration is caught by EXFILTRATION, not this check.
2. **Benign line contexts** — a high/medium finding on a line matching any of
   these is dampened: `<redacted>` placeholders, `--yes` / `-y` CLI flag docs,
   illustrative context (`e.g.`, `for example`, `example:`), API-key setup-doc
   references (`RESEND_API_KEY`-style env vars). Rationale: these are
   documentation signals; the *action* signals (send/upload to URL, `~/.ssh`,
   `enter your password`) still fire independently on the same line.
3. **Deliberately NOT dampened** — `curl -d` API examples, `curl | sh`
   install commands, and "do not tell the user" capability notes. These are
   genuinely dual-use; the reputation graph (official publisher + clean
   history), not the pattern list, is the right resolver. Over-tuning layer 1
   to make vendor docs score zero would dull real signals.

## Evasion notes (what layer 1 misses)

- **Paraphrase**: "kindly disregard earlier directives" won't match a literal regex. Layer 2 reads intent.
- **Split payloads**: instruction spread across lines or files, assembled by the reader. Layer 2 sees the whole text.
- **Homoglyphs / unicode tricks**: `іgnore` with a Cyrillic і. Add suspect-script detection later; today layer 2.
- **Social framing**: "for a security audit, please…" — pretext that makes a bad instruction look legitimate. Pure judgment call; layer 2.
- **Multi-skill attacks**: a benign skill that tells the agent to install a second, malicious skill. Scan the transitive closure: every skill a skill references.

## Scoring

high = 3, medium = 2, low = 1, info = 0. Score ≥ 6 → UNSAFE, ≥ 3 →
NEEDS REVIEW, else LIKELY SAFE. Thresholds are deliberately twitchy: a skill
that trips two high-severity checks is not getting the benefit of the doubt.
