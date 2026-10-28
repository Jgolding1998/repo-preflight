# Repo Preflight

Catch accidental disclosures before a repository becomes public. A small Python CLI scans source files and optional Git history, then reports file, line, rule, and a fingerprint. It never prints the matched value.

No account, service, third-party package, or AI key is required. Python 3.11+ and Git are enough.

```sh
python preflight.py . --tracked
python preflight.py . --tracked --history --json
python -m unittest discover -s tests -v
```

Exit codes: `0` clean, `1` findings, `2` incomplete scan. CI should fail for both nonzero codes.

## What it catches

| Rule | Why it matters |
| --- | --- |
| Credential tokens and assignments | Common provider keys, quoted JSON keys, multiline literals, and common environment fallback patterns |
| Private key headers | A private key should never be a fixture or source asset |
| Emails and personal home paths | Easy-to-miss identity leaks in examples and scripts |
| Environment files | Real `.env` files belong outside version control |
| Em dashes and configured terms | Consistent writing rules without changing code blindly |
| Oversized or unreadable text files | Scan omissions require review |

## Narrow exceptions

Use `--config rules.json` for `blocked_terms` and an `allow` list. Every exception needs an exact `rule`, `path`, `fingerprint`, and a written `reason`. Copy only the fingerprint from a redacted report. Exceptions do not support glob paths. Changing the matched value invalidates its exception.

```json
{"blocked_terms": [], "allow": []}
```

## Design choices

Rules return immutable findings, separate from reporting and file discovery. UTF-8 and BOM-marked UTF-16/UTF-32 text are supported. Escaped Windows paths in JSON are normalized for detection. Current-tree mode skips dependency folders and symlinks. Git mode uses argument arrays, never a shell, and disables filesystem-monitor helpers, signature verification, hooks, and inherited Git settings. History mode scans each reachable blob and commit identity; it can catch a value removed from the latest revision. It does not modify any file or repository.

This is a fast hygiene check, not a replacement for [Gitleaks](https://github.com/gitleaks/gitleaks), credential rotation, dependency auditing, or manual review. It does not unpack binary documents, inspect ignored files in tracked mode, identify arbitrary personal names unless configured, or prove a repository safe. Binary contents and BOM-less UTF-16/UTF-32 are skipped; large files are flagged. The token rules cover selected GitHub, OpenAI, AWS, Stripe, Slack, and Google formats, not every provider or obfuscation. Unusual field names, connection strings, encrypted archives, and obfuscated values still require a dedicated scanner and review. History mode covers locally reachable refs, not GitHub caches, forks, remote-only refs, or other clones. File and directory names are shown in reports. Fingerprints are deterministic hashes, so someone can confirm a guessed low-entropy value. Keep reports private.

## Useful workflow

1. Run the current-tree check before committing.
2. Scan history and run a dedicated secret scanner before publication.
3. Review each finding, remove the cause, and rerun the check.
4. Rotate any credential that was committed. Deleting the source line does not revoke it.

Tests use temporary repositories and synthetic values assembled in memory. They verify redaction, removed-history detection, exit codes, binary limits, and exact exceptions. No production credentials are used.
