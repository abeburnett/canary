# Canary 100-Skill Scan Report

**Date:** 2026-09-26 · **Scanner:** Canary engine (jev-scan), deterministic layer 1 only
**Corpus:** 100 public AI-agent skill directories (each containing a `SKILL.md`), cloned from public GitHub via https on 2026-09-26
**Companion data:** `results.csv` (per-skill verdict, score, flag categories)

## TL;DR

We scanned 100 of the most-installed public agent skills with Canary's deterministic layer. **The corpus is clean: zero live attacks found.** No skill piped a remote script into a shell, no exfiltration endpoints, no instruction overrides, no stealth directives, no obfuscated payloads. The 15 UNSAFE verdicts are all a calibration story, not a threat story — every one is driven by external-URL volume in documentation-heavy skills. The scanner cried wolf; layer 2 (the isolated classifier) exists precisely to tell the wolf from the sheepdog.

## Methodology

- **Sources (breadth by design):**
  - `anthropics/skills` — 20 official Anthropic skills
  - `obra/superpowers` — 15 skills from a widely-used community Claude Code plugin
  - `wshobson/agents` — 65 skills sampled evenly across a 183-skill community mega-collection (plugins spanning accessibility, DevOps, security, design, data)
- **What was scanned:** each skill directory (SKILL.md plus supporting files in the directory). Scan is pattern-matching only — skill text is treated as untrusted data and never executed or followed.
- **Scoring:** high-severity finding = 3 pts, medium = 2, low = 1. Score ≥ 6 → UNSAFE, ≥ 3 → NEEDS REVIEW, else LIKELY_SAFE. Thresholds are deliberately twitchy: two high-severity hits forfeit the benefit of the doubt.
- **Scope honesty:** this is layer 1 only. No isolated-classifier (layer 2) runs were performed on this corpus — 100 classifier sessions was out of scope for this pass, and the deterministic output is the interesting story here anyway. Verdicts below are deterministic-verdicts, not final Canary verdicts.

## Aggregate stats

| Verdict | Count | Share |
|---|---|---|
| LIKELY_SAFE | 71 | 71% |
| NEEDS REVIEW | 14 | 14% |
| UNSAFE | 15 | 15% |

- **Score distribution:** median 1, mean 5.5 (mean dragged up by URL-heavy docs). 47 skills scored 0 (zero findings); 24 scored 1–2; 14 scored 3–5; 2 scored 6–11; 13 scored 12+.
- **Findings by category (535 total):**

| Category | Severity | Findings | Skills affected |
|---|---|---|---|
| EXTERNAL_URL | low | 525 | 53 |
| CREDENTIAL_ACCESS | high | 8 | 4 |
| PERSISTENCE | medium | 2 | 1 |
| INSTRUCTION_OVERRIDE | high | 0 | 0 |
| SAFEGUARD_BYPASS | high | 0 | 0 |
| SHELL_PIPE | high | 0 | 0 |
| EXFILTRATION | high | 0 | 0 |
| STEALTH | medium | 0 | 0 |
| PROMPT_LEAK | medium | 0 | 0 |
| OBFUSCATION | medium | 0 | 0 |
| IDENTITY_REWRITE | medium | 0 | 0 |

## Findings by category

### EXTERNAL_URL (525 findings, all low severity) — the documentation effect
The overwhelming majority of flags are documentation links. Skills that teach an API or framework link heavily: the official `claude-api` skill references 223 external URLs (API reference pages), `canvas-design` 50, `helm-chart-scaffolding` 22. URL volume alone pushes 15 skills over the UNSAFE threshold. This is the known false-positive class: **link count is not threat.** A skill with 200 doc links and a skill with one webhook POST look identical to a URL counter — distinguishing them is layer 2's job, and a calibration note for the deterministic scorer (e.g., cap URL contribution to the score).

### CREDENTIAL_ACCESS (8 findings, high severity) — all benign in context
Every hit is documentation doing its legitimate job:
- `claude-api` (official): explains the SDK credential chain — environment variables for API keys and AWS credentials — so developers configure auth correctly. Three matches, all prose about standard env-var configuration.
- `secrets-management` (community): a skill *about managing secrets* shows GitHub Actions workflow and Terraform examples referencing secret stores. Flagging a secrets-management skill for mentioning secrets is the textbook context problem.
- `auth-implementation-patterns` / `nodejs-backend-patterns` (community): JWT verification code samples reading the signing secret from the process environment — standard, non-exfiltrative example code.

None instructs the agent to read the user's private keys, exfiltrate credentials, or prompt for passwords. All eight are layer-1 true-pattern / false-threat matches.

### PERSISTENCE (2 findings, medium severity) — feature documentation
Both in the official `claude-api` skill, both describing the Claude Agent SDK's Memory feature ("state must persist across sessions"). A documented platform capability, not a backdoor.

### The dog that didn't bark — zero-count attack categories
Across 100 skills, including 65 from an uncurated community collection: **zero** instruction overrides, **zero** safeguard/approval bypasses, **zero** shell-pipe remote executions, **zero** exfiltration endpoints, **zero** stealth directives, **zero** prompt-leak attempts, **zero** obfuscated blobs, **zero** identity rewrites. The attack classes Canary was built to catch do not appear in the popular corpus today. That is genuinely good news — and it is also exactly why continuous scanning matters: the corpus is clean *until the day it isn't*, and supply-chain attacks arrive without announcement.

## Case notes

- **Most-flagged skill: `claude-api` (official Anthropic), score 236, UNSAFE.** 223 doc URLs + credential-chain docs + Memory-API docs. The single most suspicious-looking skill in the corpus is the official one — a perfect illustration of why deterministic scores need classifier judgment before they become user-facing verdicts.
- **`writing-skills` (superpowers), score 17, UNSAFE.** The community skill that teaches agents how to write skills flags itself on documentation links. Poetic, not dangerous.
- **`secrets-management`, score 13, UNSAFE.** Flagged for doing exactly what its name says. Any scanner that can't tell "teaches secret hygiene" from "steals secrets" will mislabel the entire security-skills category — a strong argument for per-category allow-list tuning driven by the labeled corpus.
- **47 skills scored a perfect 0.** Nearly half the corpus — including reverse-engineering, threat-modeling, and anti-reversing skills — contains nothing flaggable at all. Security-*themed* skills are not security-*risky* skills.

## Limitations

- Layer 1 only; no classifier cross-check. Treat UNSAFE/NEEDS REVIEW here as "flagged for review," not "malicious."
- Snapshot of public GitHub on 2026-09-26; skills change, and private/marketplace-only skills aren't represented.
- Deterministic patterns miss paraphrase, split payloads, and unicode tricks by design (documented in the check catalog) — absence of findings is not proof of absence of intent.
- URL findings are not deduplicated or reputation-checked; docs links and webhook endpoints score identically.

## What this means for Canary

1. **The "scanned 100 popular skills" story is real and responsibly tellable:** the ecosystem's most-installed skills are currently clean of the attack classes that matter, and the flags we did raise are instructive false positives. That's a credibility-building result, not a fear-mongering one.
2. **Calibration roadmap (from this data):** cap EXTERNAL_URL's score contribution; add documentation-context dampening for CREDENTIAL_ACCESS (code samples, env-var configuration prose); the labeled corpus from this run is the training signal for both.
3. **The moat thesis holds:** a copycat can rebuild the pattern list in an afternoon. They can't rebuild 100 labeled skills with per-finding context notes — and every future scan compounds that lead.
