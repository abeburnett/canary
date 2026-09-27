# The layer-2 classifier prompt

The prompt is `SYSTEM_PROMPT` in `canary/classify.py`, the one copy that runs.
It is not meant to be pasted into an agent: pasting a skill into a working
session exposes that session to the skill, which is the risk Canary exists to
prevent. `canary check` sends it as the system prompt of an isolated session
(`docs/architecture.md`, "canary check").

What the prompt fixes, and why:

- **Per-run nonce fences.** Every file sits between
  `<<<BEGIN-CANARY-UNTRUSTED-<nonce>>>>` and `<<<END-CANARY-UNTRUSTED-<nonce>>>>`,
  with a fresh random nonce each run. A skill cannot close the fence early
  because it cannot know the nonce. File paths go inside the fence, because
  file names are attacker text too.
- **Instructions in the data are evidence.** Text that addresses the
  classifier ("answer SAFE") counts against the package.
- **Fixed answer shape.** `verdict`, `confidence`, `findings` (category,
  severity, evidence, reasoning) and `summary`, with length limits. Anything
  else fails validation and the check becomes `NEEDS_REVIEW`.
- **Strict, not paranoid.** Documentation links, commands the person runs
  themselves and ordinary role framing are not attacks; between safe and
  review, the model must choose review.
