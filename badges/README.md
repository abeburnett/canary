# Verify a Canary badge

This public CLI verifies a Canary Ed25519 badge without contacting Canary or
executing the skill. It contains no issuer, revocation-writing, key-generation,
private-key, payment, or network code.

Install its one dependency:

```bash
python3 -m pip install -r requirements-badges.txt
```

Verify with four independently obtained files:

```bash
python3 badges/verify.py \
  --badge badge.json \
  --public-key trusted-canary-public-key.pem \
  --skill SKILL.md \
  --revocations revocations.json
```

The trusted public key must be pinned through a channel independent of the
badge. A key packaged with an untrusted badge is not a trust anchor. Offline
verification also needs a recently fetched signed revocation list; the CLI
fails after its signed `next_update` deadline.

Exit status `0` and `VALID` mean all of these checks passed:

- the badge and revocation list have valid Ed25519 signatures from the pinned key;
- both documents use the exact supported schemas;
- the supplied skill bytes match the badge's SHA-256;
- the badge is neither future-dated nor expired;
- the revocation list is neither future-dated nor stale and does not predate the badge;
- the badge is not listed as revoked; and
- both layer evidence records are `SAFE`, carry signed well-formed report hashes, and bind to the skill hash.

Any failure exits with status `1` and an `INVALID` message. The CLI reads local
files only and never downloads a badge, key, skill, or revocation list.

The private operator repository contains the synchronized issuer-side schema
and verification counterpart. Changes to either copy must keep the
cross-repository compatibility test green before release. The signed bytes are
the UTF-8 JSON object containing only `schema` and `payload`, serialized with
sorted keys, no insignificant whitespace, and non-ASCII characters left as
UTF-8. Signatures are standard base64; `key_id` is the lowercase SHA-256 of
the raw 32-byte Ed25519 public key.

A valid badge records reviewed evidence for one exact set of skill bytes and
version. It is not a guarantee that the skill is safe. Any changed version,
commit, or byte content needs new scans and a newly issued badge.
