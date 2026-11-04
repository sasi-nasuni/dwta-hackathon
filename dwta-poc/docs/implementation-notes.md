# Implementation notes (v1.0)

What the build learned and where it departs from `spec/DwTA-Spec-v1.ipynb`. Each item should be folded back into the spec
as a v1.x revision.

## Verification items: answers

| ID | Question | Answer (measured on the reference Mac) |
|---|---|---|
| V-01 | Where does `vfs_full_audit` write, and what are the op names? | A dedicated file through Samba's per-class debug log: `log level = 1 full_audit:1@/var/log/samba/audit.log`, with `debug hires timestamp` (µs). Ops seen: `connect`, `disconnect`, `openat`, `create_file` (args: access mask, file/dir, disposition, path), `pwrite_send`, `close`, `renameat` (src, dst), `unlinkat`, `mkdirat`. Paths are absolute (`/srv/shares/<share>/…`). `%m` is lower-cased. |
| V-02 | Source IP Samba sees for the Mac's own connections | The lab network gateway (`10.250.x.1`), with the Mac's real machine name. The collector tags these `client_origin = host`. |
| V-03 | Finder / `mount_smbfs` on a non-445 port | Works: `mount_smbfs //jdoe:<pw>@127.0.0.1:14450/finance <dir>`. |
| V-04 | Magika on linux/arm64, offline | `magika 1.0.3` + `onnxruntime 1.31` wheels for cp314 aarch64; the model ships in the wheel. Classifier container ≈ 70 MiB RAM. |
| V-05 | YARA-X wheel on linux/arm64 | `yara-x 1.22.1` (cp314 aarch64). |
| V-06 | Postgres 16 in the lab | `postgres:16-alpine` healthy in ~3 s; ≈ 68 MiB RAM. Whole lab ≈ 223 MiB. |
| V-07 | Current MalwareBazaar CSV columns | Not checked (no download). The fabricated feed uses the documented 14-column export format. |

## Deviations from spec v1.0

| Spec | Implemented | Why |
|---|---|---|
| SMBS-10 `vfs objects = fruit streams_xattr full_audit` | `full_audit` only | Docker Desktop bind mounts have no xattrs; with fruit/streams_xattr loaded, rename and delete fail (`NT_STATUS_NOT_SUPPORTED`). The collector ignores `._*`/`.DS_Store` (COL-40). |
| SMBS-11 prefix `%T\|%u\|%I\|%m\|%S` | `%T\|%u\|%I\|%m\|%S\|%d` | `%d` (smbd process id) is needed to track open handles per connection (COL-04). Event time comes from the µs debug header. |
| Python services on `python:3.12-slim` | `python:3.14-slim-bookworm` | Same version as the host; every dependency has cp314 arm64 wheels. |
| `run/simclock.json` | `run/simclock.jsonl` (append-only, one entry per step) | Simpler, crash-safe append; readers pick the latest anchor ≤ event time. |
| `run/alerts.jsonl` | `run/alerts/<service>.jsonl` | One writer per file: no interleaving between containers. The ledger `alerts` table is the combined view. |
| `encrypt`: AES-256-CTR via openssl | SHA-256 counter-mode keystream XOR (stdlib) | Keeps the host simulator stdlib-only; output is high-entropy and reversible, which is all the lab needs. |
| SIM-08 `restore` undoes the whole run | `dwta-sim restore` = **Targeted Restore stand-in**: encrypted files come back, planted files and notes stay. `dwta-lab reset` returns to a clean lab | Matches the core idea: demonstrates exactly what Targeted Restore leaves behind. |
| Ledger §6.3: `decision` on `review_items` | Separate `review_decisions (incident_id, item_key)` | Decisions are per item, independent of mode, and survive a re-plan (ENG-05). |
| Ledger §6.3: `artifacts.status` | `artifacts.content_status` (ok / gone_before_read / changed_since_event); presence lives in `files.status` (present / deleted / replaced) | Clear split between "what we read" and "where the file is now". |
| §6.6 one review list per mode | One `review-list.json` with `modes.rules` and `modes.rules_ai` | One file per incident; the UI toggle reads both. |
| Incident barrier: classifier high-water ≥ `detected_sim_ts` | Classifier's *caught-up wall clock* ≥ incident received + 7 s | Simulated detection time is usually later than the last event, so a sim-time barrier would always time out. |
| SIM-06 actions expose `plan(step)` + `execute(op)` | One `run(ctx, step)` function per action, registered by decorator | Same goal (new actions never touch the runner) with less ceremony; revisit if partial-plan execution is needed |
| Config paths `specs/<name>.toml` | `specs/config/<name>.toml` | Keeps configuration apart from schemas and YARA rules |
| SMBS-06 healthcheck via `smbclient -L` | TCP check on port 445 in the image `HEALTHCHECK` | Same signal without credentials |
| Collector `both` mode | Watcher deletes are dropped when the file still exists after the grace period; identical inotify events collapse | A rename onto an existing file (office save) makes inotify report the target as deleted, twice. |

## Audit of 2026-11-03 (code vs spec v1.0)

78 MUST requirements checked. Fixed in this pass: `tie_break` and `replaced_original` (same user, `within_seconds`) now read from config; R-W5/FEED-MATCH severities in `rules.toml`; SMBC-04 SMB2 floor; SMBC-05 `list_shares` and recursive `copy_dir`; SMBS-14 audit log rotation at 50 MB with the tailer draining the old file; SIM-05 failed operations recorded as `result = error`; SIM-10 `--speed realtime`; LED-06 `dwta-lab export-ledger`; CLS-04 race (see the spec v1.12 change); the journal is flushed after every batch so the classifier sees events within ~0.2 s.
Still open by design: AV-05 verdict reuse (needs a real scanner, v2); RBQ-04 per-version read counter is covered by unit tests, not yet by an acceptance test.

## Known limits

- The watcher only sees writes made inside Docker's VM; files copied straight into `lab/<instance>/data` from macOS are invisible to it (spec §3.2).
- Magika is unsure (score < 0.8) on synthetic ELF stubs and word-salad text, so `rules_ai` falls back to the rules typer for those, as designed.
- Executing the restore-exclusion manifest (quarantine move + real Targeted Restore) is not built in v1 (D-17).
- Core idea step ⑤ (AV rescan of flagged files): v1 has the `AvScanner` hook (`services/incident/src/dwta_incident/av.py`), the `S-AV` weight in `ranking.toml`, and `av_*` columns (migration 003). The only scanner is `none`, so every listed file shows `not_scanned`; the `clamav` scanner and container come in v2 (spec §5.10.4, §8.3).
