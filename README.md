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
| Credential tokens and assignments | Common provider keys, quoted JSON keys, typed, `:=`, `=>` and subscript assignments, multiline literals, unquoted values with embedded `#` or trailing `#` comments, simple unquoted shell literals before `;`, and common environment fallback patterns |
| Private key headers | A private key should never be a fixture or source asset |
| Emails and personal home paths | Easy-to-miss identity leaks in examples and scripts |
| Environment files | Real `.env` files belong outside version control |
| Configured terms | Optional terms supplied explicitly in the rules file |
| Em dashes (optional) | Enable the writing-style rule with `--check-style` |
| Oversized or unreadable text files | Scan omissions require review |

Writing-style checks are off by default. Add `--check-style` to include the em dash rule in current-file and history scans. This repository enables it explicitly in CI.

## Narrow exceptions

Use `--config rules.json` for `blocked_terms` and an `allow` list. Every exception needs an exact `rule`, `path`, `fingerprint`, and a written `reason`. Copy only the fingerprint from a redacted report. Exceptions do not support glob paths. Changing the matched value invalidates its exception. For unreadable and oversized files the matched value is the content itself: unreadable text uses a content hash, a historical oversized object uses its object ID, and an oversized working file hashes only its first 2 MiB plus one byte, so a change past that point keeps the exception.

Config files accept only these two fields, reject duplicate keys, and are limited to 2 MiB, 128 blocked terms and 4,096 exceptions. History traversal ignores replacement objects and graft files.

This repository uses `--config preflight-rules.json` for its self-scan. It allows one exact synthetic test literal that also appears in earlier revisions. Review and replace that exception list when adopting the tool for another repository.

```json
{"blocked_terms": [], "allow": []}
```

## Design choices

Rules return immutable findings, separate from reporting and file discovery. UTF-8 and BOM-marked UTF-16/UTF-32 text are supported. Escaped Windows paths in JSON are normalized for detection. Current-tree mode skips dependency folders, symlinks and Windows junctions without descending into them. An unreadable directory, unreadable file attribute or unsupported file or directory reparse point exits `2`. Tracked mode also checks parent directories and treats a missing indexed file as incomplete; stage an intentional deletion before scanning. Use a fully local checkout if cloud placeholder folders prevent a complete scan.

Tracked mode reads working files, not staged index contents, and requires a full working tree rather than a sparse checkout. It does not descend into submodules or directories that replace indexed files. Quoted source construction can also look like a credential literal; review such findings before creating an exact exception.

The shell extension checks a simple leading assignment, optionally prefixed with `export`, before `;`, `&&`, `||` or `&` in `.sh`, `.profile`, `.bash_profile`, `.bashrc`, `.zprofile` and `.zshrc` files. It preserves escaped operators and embedded `#` within the literal. It does not interpret shell commands, resolve expansions or follow arbitrary compound statements.

Git commands use argument arrays, never a shell. Inherited `GIT_*` variables are removed, global and system configuration are ignored, and filesystem-monitor helpers, signature verification and hooks are disabled. Lazy fetching and Git transport protocols are disabled, so missing objects fail the scan without running a remote helper. Repository-local configuration, including its includes, is still read. The scanner reads raw objects without checkout filters and does not modify the repository.

History mode scans locally reachable blobs, including blobs tagged without a filename, plus raw commit and annotated-tag metadata. This includes commit messages, tag messages, author, committer and tagger identities. Reports use object IDs and virtual paths for metadata and unnamed blobs; matched values remain redacted. Binary metadata is flagged instead of silently skipped.

Historical blobs are checked at every path recorded in commit diffs, including separate merge-parent diffs, plus the representative name supplied by Git object traversal. Identical content renamed from `.env` to a documentation file still receives its original environment-file and configuration checks. Path records use NUL delimiters, and exact path exceptions remain specific to each historical name. Each object/path scan counts toward the existing 100,000-scan and 64 MiB sampled-content bounds, so repeatedly renamed content can exhaust a budget sooner. Git path discovery also shares the history deadline and output cap; large merge diffs can exceed that cap even when the unique object count fits. Trees reachable only through tags retain their representative traversal names; their other path aliases are not exhaustively enumerated.

History scans require a full clone. A shallow clone exits `2` with guidance to fetch complete history, for example `git fetch --unshallow`; the scanner never fetches automatically. The local scan is bounded to 100,000 reachable objects and 64 MiB of sampled historical content. Each object is limited to 2 MiB; larger objects are flagged. Object types and sizes come from one `git cat-file --batch-check` call, and contents are read in `git cat-file --batch` groups that fit the output cap, so process count does not grow with history length. A missing object or inconsistent batch reply exits `2`. The history phase has a 120-second budget checked between object scans. Git commands use the smaller of 60 seconds or the remaining history budget, with an 8 MiB output cap. An in-progress file check completes before the deadline is checked again. Exceeding an aggregate limit exits `2`, rather than reporting a complete scan.

This is a fast hygiene check, not a replacement for [Gitleaks](https://github.com/gitleaks/gitleaks), credential rotation, dependency auditing, or manual review. It does not unpack binary documents, inspect untracked files in tracked mode, identify arbitrary personal names unless configured, or prove a repository safe. UTF-8 text remains scanned when it contains NUL bytes. Other NUL-containing binary data is checked only for recognizable token formats and private-key headers; BOM-less UTF-16/UTF-32 and encoded or packed contents are not decoded. Large files are flagged. The token rules cover selected GitHub, OpenAI, AWS (`AKIA` and 20-character `ASIA` IDs), Stripe, Slack, and Google formats, not every provider or obfuscation. Credential field names are limited to 128 characters and simple environment lookup arguments to 1,024 characters. Unusual field names, nested expressions, connection strings, encrypted archives, and obfuscated values still require a dedicated scanner and review. History mode covers locally reachable refs, not GitHub caches, forks, remote-only refs, or other clones. File and directory names are shown in reports. Fingerprints are deterministic hashes, so someone can confirm a guessed low-entropy value. Keep reports private.

## Useful workflow

1. Run the current-tree check before committing.
2. Scan history and run a dedicated secret scanner before publication.
3. Review each finding, remove the cause, and rerun the check.
4. Rotate any credential that was committed. Deleting the source line does not revoke it.

Text reports escape control and non-ASCII characters in filenames so a captured path cannot rewrite terminal output. Parse JSON reports to recover exact filenames for tooling or exceptions.

Tests use temporary repositories and synthetic values assembled in memory. They verify redaction, removed history, graft and replacement handling, tagged blobs, commit and tag metadata, shallow clones, scan budgets, exported environment assignments, malformed configuration, exact exceptions and bounded adversarial inputs. No production credentials are used.
