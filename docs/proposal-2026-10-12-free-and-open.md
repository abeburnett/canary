# Proposal: retire the paid tier and make SkillCanary free

Status: proposal for the owner, 2026-10-12. Nothing here has been done.
Publishing, releases, site deploys and anything in Stripe stay owner
decisions.

The owner decided on 2026-10-12 (future-think ticket
`wayfinder/tickets/06-venture-decisions.md`) that SkillCanary becomes free and
open source, as a reputation piece, with a page on abeburnett.com. The paid
tier was Team at $19/month per GitHub organization (private-repository CI,
hosted scans) and verified badges at $99/year per skill.

I recommend four steps, in this order. Each step can ship alone.

## 1. Release the plain-verdicts change as 0.1.2

The owner runs 0.1.1, which shows the verdict without a recommendation. This
branch (`program/2026-10-12-plain-verdicts`) adds the recommendation, the
plain risks and the quoted lines. It needs the usual gates before merge
(`premerge-review`, the full test suite, a done-when audit), then the owner's
signing and notarization pipeline, the Homebrew recipe bump and the VM e2e
run. After installing it, the owner runs `canary setup` again.

## 2. Remove paid features from the public repo (one PR)

| File | Change |
|---|---|
| `scripts/action.py` lines 185–189, `action.yml` line 44 | Drop the `CANARY_API_TOKEN` requirement for private repositories, so the Action runs the same scan everywhere. Update `tests/test_action.py` (`test_private_repository_requires_token_presence_without_disclosure`). |
| `docs/github-action.md` | Remove the private-repository token setup. |
| `badges/`, `requirements-badges.txt`, `.github/PULL_REQUEST_TEMPLATE/skill-registry.md` | Delete: badges are not issued. |
| `canary/evidence.py`, `docs/evidence-contract.md`, `tests/test_evidence*.py`, `tests/vectors/evidence-v1.json` | Keep `canary evidence` only if a public use remains (it was built for hosted badges). I recommend deleting it with the badges; its only caller is the `canary evidence` command itself (`canary/cli.py`). |
| `docs/marketplace-listing.md`, `docs/codex-brief.md`, `docs/codex-facts.md` | Delete or mark historical: they describe the paid launch. |
| `docs/architecture.md` | Remove the Team token and badge sections. |
| `canary/frontdoor.py` and `skills/canary/SKILL.md` | Point "When `canary` is not installed" at the GitHub README or the abeburnett.com page instead of skillcanary.com, once step 3 decides the domain. |

## 3. Replace skillcanary.com with a page on abeburnett.com

- **Page.** Add `/skillcanary` (or `/building/skillcanary`) to
  `~/workspace/abeburnett-com/site/`, built from the new README: what it
  protects against, the example finding, the three recommendations, the
  measured table, install, and the GitHub link. The home page row already
  says "Open source" and links to skillcanary.com; point it at the new page.
  That repository has uncommitted work from another session, so the page goes
  on its own branch.
- **Domain.** Redirect skillcanary.com to the new page (a Cloudflare
  redirect rule) and keep the domain registered for a year, so old links and
  the 0.1.1 skill text keep working.
- **Old site.** Stop deploying `canary-pro` `site/` (Cloudflare Pages builds
  it from branch `program/2026-09-26-paid-launch`), and remove its pricing
  and early-access pages (`site/index.html`, `site/early-access.html`). The
  installed SkillCanary skill (0.1.1 and `main`) tells agents to send people
  to https://skillcanary.com to set it up; move the `/start` install steps to
  the new page before turning the old site off.

## 4. Close the paid back end

- **Stripe.** `canary-pro/stripe/README.md` describes test-mode products
  ("Canary Team", "Canary Verified Badge"). I did not check the Stripe account
  for live products, payment links or customers. If any exist, archive the
  products and payment links, and tell any subscriber before cancelling.
- **Hosted scans and badges.** Codex owned hosted accounts, billing, hosted
  scanning and badge issuance (owner decision 2026-09-27). Ask the Codex
  session's owner to stop any scheduled jobs and to confirm nothing is
  deployed. The badge revocation list lapsed on 2026-10-04 and needs no
  action.
- **Repository.** Archive `abeburnett/canary-pro` (private) on GitHub after
  steps 3 and 4. Archiving keeps the history and stops changes.
- **Worktrees.** The stale Codex clone at
  `~/Documents/Codex/2026-09-26/can-you-help-me-with-getting/work/hosted`
  holds branch `codex/2026-09-27-hosted`; decide whether to delete it.

## Decisions for the owner

1. Release 0.1.2 now, or fold step 2 into it first? I recommend releasing now:
   the recommendations fix the problem that prompted this, and step 2 changes
   nothing a Mac user sees.
2. Keep or delete `canary evidence`? I recommend delete.
3. The page path on abeburnett.com, and whether skillcanary.com redirects or
   lapses. I recommend a redirect for one year.
