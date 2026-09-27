# GitHub Marketplace listing draft

## Listing copy

- **Title:** Canary Skill Scan
- **Tagline:** Scan AI skill files for prompt-injection risk before trusting them.
- **Category:** Security
- **Branding:** Yellow shield

### Description

Canary scans AI skill files for prompt-injection and malicious-instruction
signals before an agent trusts them. The action bundles a fixed, calibrated
deterministic scanner, runs without executing scanned content, and reports
safe, review, or unsafe with file-and-line findings. Public repository scans
are free. Private repositories require a Canary Team API token.

The Action provides deterministic layer-1 screening. A `safe` result is a
likely-safe layer-1 verdict, not Canary's separate two-layer certification.

## Owner publish checklist

This repository contains a draft only. The owner performs every GitHub
Marketplace publication step.

- Review the final public diff and confirm the malicious fixture remains sanitized.
- Run `python3 -m unittest discover -s tests -v` and `git diff --check` on the release candidate.
- Commit the candidate and record its immutable full commit SHA.
- Replace quickstart placeholders with the reviewed release commit SHA.
- Confirm `action.yml`, README inputs, outputs, branding, pricing language, and private-token limitation agree.
- Create the GitHub release or tag intended for the listing.
- In GitHub's release UI, choose **Publish this Action to the GitHub Marketplace**.
- Review the Marketplace terms, categories, listing copy, and preview before the final public click.
- After publishing, open the public listing and run the pinned quickstart in a disposable public repository before announcing it.
