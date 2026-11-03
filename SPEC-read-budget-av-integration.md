## Read budget and antivirus integration

> **Status:** draft for review. Builds on the follow-up writes section (`FW-`). Requirement IDs use the prefix `RB-`.
> Items marked **VERIFY** need confirmation from the Edge team. They affect the product story, not the POC.

### Purpose

DwTA must cost less storage I/O per file update than full-file antivirus scanning, and the POC must **prove it with measured numbers**, not claims. In the product, DwTA should reuse reads the antivirus pass already makes rather than add new ones.

### Background (verified)

- Nasuni Antivirus Protection scans the entire file, not just the changed part. It runs per scan cycle: scheduled batches plus a scan with every snapshot, or on each file close when "Check files immediately" is enabled on an SMB volume. Unchanged files are never rescanned. ([Antivirus Protection](https://docs.nasuni.com/docs/nasuni-antivirus-protection))
- A full scan with a third-party scanner would pull all data into the Edge cache. (same source)
- ClamAV's clean-file cache hashes the file first and then looks it up, so it saves scanning CPU, not reads. ([ClamAV cache.h](https://remotebranch.eu/Stowage/clamav/src/branch/dev/1.5.1/libclamav/cache.h))
- ClamAV 1.5 computes SHA2-256 for its clean-file cache and adds scan callbacks, including file-type and pre-hash hooks. Its new scan function can return the computed hash. ([ClamAV blog, Oct 2025](https://blog.clamav.net/2025/10))

### Design rules

- **RB-R1 – Bounded read per evaluation.** An evaluation reads at most the head window (65,536 bytes) plus the tail window (65,557 bytes), 131,093 bytes in total, or the whole file once if it is 128 KiB or smaller. This is the FW-K1 read window, now a hard limit.
- **RB-R2 – Whole-file reads only for hashing.** A file is read in full only when FW-H1 requires a hash.
- **RB-R3 – Zero content reads for derived work.** Feed ingest and matching, renames, deletes, ranking, incident queries and narratives never read file content.
- **RB-R4 – One whole-file read per version.** A version's hash is computed once and never recomputed. Every later step uses the ledger.
- **RB-R5 – History is never read through the Edge.** Retroactive hunts over older versions (for example YARA) run against storage-side copies in the product. The POC only reads current files.

### Evaluation modes

**RB-M1 – Two modes**, matching how antivirus scheduling already works:

| Mode | When a dirty file is evaluated | Trade-off |
|---|---|---|
| `immediate` | On close, coalesced as in FW-C3 | Fastest detection, most evaluations |
| `per_snapshot` | Once per snapshot cycle, for every path dirtied since the last cycle | Ten saves in one cycle cost one evaluation; detection waits for the cycle |

**RB-M2 – Snapshot cycle in the POC.** The lab has no real snapshots, so a configurable timer on the simulated clock stands in for the snapshot cycle.

**RB-M3 – Configuration**

```yaml
read_budget:
  head_bytes: 65536
  tail_bytes: 65557
  small_file_full_read_bytes: 131072
  hash_size_cap_bytes: 67108864      # FW-H2
evaluation:
  mode: immediate                    # immediate | per_snapshot
  snapshot_interval_seconds: 60      # per_snapshot only
baseline:
  clamav_meter: rchar                # rchar | modeled
```

### Read accounting (POC)

- **RB-A1 – One meter for every read.** All content reads go through a single `ReadMeter` wrapper. It records the bytes read, the path, the version and the reason (`head`, `tail`, `small_file`, `hash`). Code that reads file content any other way fails review.
- **RB-A2 – ClamAV baseline.** The baseline is recorded two ways:
  - **Measured (`rchar`):** the change in the clamd process's `rchar` counter (`/proc/<pid>/io`) around each scan, excluding signature-reload windows.
  - **Modeled:** the file's size, once per scan the active mode would trigger: every close in `immediate` mode, once per dirty file per cycle in `per_snapshot` mode.
  
  The two are reported side by side; a large gap between them is investigated, not hidden.
- **RB-A3 – Schema additions**, extending FW-L1:

```sql
ALTER TABLE file_version ADD COLUMN bytes_read   INTEGER NOT NULL DEFAULT 0;
ALTER TABLE file_version ADD COLUMN read_reasons TEXT;   -- e.g. 'head,tail,hash'

CREATE TABLE baseline_scan (
  id          INTEGER PRIMARY KEY,
  ts          TEXT    NOT NULL,                -- simulated clock
  volume      TEXT    NOT NULL,
  path        TEXT    NOT NULL,
  mode        TEXT    NOT NULL CHECK (mode IN ('immediate','per_snapshot')),
  bytes_read  INTEGER NOT NULL,
  method      TEXT    NOT NULL CHECK (method IN ('rchar','modeled'))
);
```

- **RB-A4 – Metrics endpoint.** `GET /metrics/reads?from=<ts>&to=<ts>` returns:

```json
{
  "window": {"from": "2026-11-04T00:00:00Z", "to": "2026-11-04T23:59:59Z"},
  "mode": "immediate",
  "evaluations": 1300,
  "dwta_bytes_read": 0,
  "dwta_by_reason": {"head": 0, "tail": 0, "small_file": 0, "hash": 0},
  "files_hashed": 0,
  "baseline_bytes_read": {"rchar": 0, "modeled": 0},
  "ratio_vs_modeled": 0.0
}
```

- **RB-A5 – Demo panel.** The UI shows DwTA's bytes read next to the ClamAV baseline for the same workload, with the ratio and a breakdown by reason.

### Antivirus integration (product; not built in the POC)

- **RB-P1 – Harvest, don't re-read.** When antivirus is enabled and the engine is ClamAV 1.5 or later, DwTA takes the SHA-256 and file type from the antivirus pass. Its own reads for that file are then limited to the tail window, or zero where the antivirus pass already identified tail-defined formats (**VERIFY-RB-3**).
- **RB-P2 – Never in the antivirus path.** DwTA consumes antivirus results asynchronously. A DwTA failure never delays or changes an antivirus verdict.
- **RB-P3 – Trust only full reads.** A harvested hash is used only for files the antivirus pass read in full. For files it skipped or truncated (encrypted, over size limits), DwTA applies its own policy (FW-H1, FW-H2).
- **RB-P4 – Retroactive hunts storage-side.** YARA or hash hunts over historical versions run near object storage, on executable-class versions only, never through the Edge cache (RB-R5).
- **RB-P5 – Later: entropy on written data.** Computing entropy on data as it is written costs CPU, not reads, and adds an encryption signal. It complements DwTA and is out of scope for now.

### Acceptance scenarios

All scenarios use harmless artifacts and the simulated clock.

- **RB-AT-01 – Bounded read on a large document.**
  *When* a 50 MB PDF is overwritten with another PDF,
  *then* that evaluation's `bytes_read` is at most 131,093 and no `hash` reason is recorded.

- **RB-AT-02 – Feed ingest reads nothing.**
  *Given* a ledger with executable-class versions,
  *when* a feed of 10,000 hashes is ingested and matched,
  *then* DwTA's total `bytes_read` is unchanged and the expected matches are reported.

- **RB-AT-03 – Rename reads nothing.**
  *When* `notes.txt` is renamed to `notes.exe`,
  *then* the rename version has `bytes_read = 0`.

- **RB-AT-04 – One whole-file read per version.**
  *Given* the test executable is written once,
  *when* it is matched, ranked, included in an incident and narrated,
  *then* exactly one `hash` read is recorded for that version.

- **RB-AT-05 – Comparison workload.**
  *When* the standard workload runs (1,000 new files, mostly Office documents, PDFs and images, with a few archives and test executables, followed by 200 overwrites and 100 appends),
  *then* `/metrics/reads` reports DwTA and baseline bytes for both modes.
  *Proposed target, to confirm in the lab:* DwTA reads at most 25% of the modeled baseline in `immediate` mode.

- **RB-AT-06 – Per-snapshot coalescing.** *(should-have)*
  *When* one file is saved 10 times inside a single snapshot cycle,
  *then* `per_snapshot` mode records 1 evaluation and 1 baseline scan, and `immediate` mode records up to 10 of each.

- **RB-AT-07 – Current files only.**
  *For* every evaluation in the workload, the `ReadMeter` shows reads only from the current file at the evaluated path.

### Known limits

- **RB-G1 – Bytes read are not cache misses.** In the lab everything is on local disk. On a real Edge the cost depends on whether the bytes are still in cache, so the ratio must be re-measured there.
- **RB-G2 – The baseline is approximate.** The `rchar` counter can include reads unrelated to scanning, and the modeled number assumes the whole file is read even above ClamAV's size limits (**VERIFY-RB-3**).
- **RB-G3 – Not an antivirus replacement.** DwTA reads less because it doesn't inspect the content of non-executable files. ClamAV still covers known-malicious content in all file types.

### Open questions

1. **VERIFY-RB-1:** Which ClamAV version does the Edge ship? Version 1.5 or later is needed for SHA2-256 hashing and the scan callbacks.
2. **VERIFY-RB-2:** Does the Edge use libclamav directly or clamd? The callbacks and hash output are libclamav APIs.
3. **VERIFY-RB-3:** Does the antivirus pass read files above 25 MB at all, and does it report container or tail-defined formats?
4. **VERIFY-RB-4:** Can a per-snapshot evaluation get the snapshot's list of changed files directly?
5. **Target ratio:** is "at most 25% of baseline" the right bar for the demo, or should the team just report what it measures?

### Implementation mapping (48-hour plan)

| Requirement | Lane | Step |
|---|---|---|
| RB-R1 to RB-R4, `ReadMeter` (RB-A1), schema (RB-A3) | Security engineer with backend engineer | Step 3 |
| ClamAV baseline meter (RB-A2) | Security engineer | Step 4, with the ClamAV baseline |
| `/metrics/reads` (RB-A4), demo panel (RB-A5) | Backend engineer | Step 4 |
| `per_snapshot` mode (RB-M1, RB-M2) | Backend engineer | Step 4 (should-have) |
| RB-AT-01 to 05, 07 | PM / QA | Steps 3-4 |
| RB-AT-06 | PM / QA | Step 4 (should-have) |
| RB-P1 to RB-P5 | Not built; product notes | — |
