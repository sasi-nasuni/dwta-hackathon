## Restore-time suggestion

> **Status:** implemented in the Edge integration (dwtad + Portal), 2026-11-04. Separate spec; not yet merged into `DwTA-Spec-v1.ipynb`. See "Implementation notes" at the end.
> Requirement IDs use the prefix `RT-`. Builds on the core idea (pre-restore review), the ledger (§6.3) and the incident engine (B10).

### Purpose

Today the admin must type a restore time from memory. DwTA already knows, for every file written, who wrote it, from where, when, what it really is and what flagged it. This feature uses that ledger to **suggest** a restore time: the latest snapshot before the attacker's first trace. The admin then confirms or edits it.

It is a **fixed, rules-based** engine: deterministic, explainable, every threshold in configuration, and no file reads.

### Where it fits in the core idea

```
 ① Incident detected (detection time, user, IP, machine, volumes)
          │
 ①a NEW: DwTA SUGGESTS a restore time: cautious / recommended / aggressive, each with its evidence
          │
 ② Admin CONFIRMS a suggestion or enters their own restore time      (suggest only, never auto-applied)
          │
 ③ … ⑧ unchanged: review window, scoring, AV rescan, review list, remove/keep, restore without removed files
```

### Inputs

| Input | Source |
|---|---|
| Incident | Detection time, user, IP, machine, volumes (product detector; B9 in the lab) |
| File history | Ledger: `artifacts` (writer, IP, machine, time, hash, type), `alerts` (rule IDs), `feed_matches`, `files` |
| Snapshot schedule | Lab: one snapshot every **5 minutes** on the simulated clock. Product: the volume's real snapshot list |
| Settings | `specs/config/restore_suggest.toml` (below) |

### Evidence model

Every ledger event (a file version written) in the lookback period gets **one evidence class**:

| Class | Event | Examples |
|---|---|---|
| **Strong** | The file carries a strong content signal | Feed match (`FEED-MATCH` / R-W5), disguised executable (R-W2), turned into an executable (R-W6), YARA hit (R-W4), AV detection (S-AV) |
| **Medium** | Written by the incident's identity, where that identity is **new** to the volume (first seen within the lookback) | First write by `svc-backup` or `SRV-BKP01` (`10.250.1.66`) on `finance` |
| **Weak** | Written by the incident's identity, where that identity is **established** on the volume (seen before the lookback started) | A long-standing service account doing its routine writes |

"Identity" means any of user, client IP or machine name. Matching any one is enough, which also covers stolen credentials (a known user from an unknown machine).

### The decision procedure

1. **Seed the chain.** Every event that matches the incident's user, IP or machine on the incident's volumes, from the start of the lookback to detection.
2. **Grow the chain** until nothing new joins:
   - **same hash:** any event whose SHA-256 equals a chain member's (the same payload copied elsewhere);
   - **same machine or IP:** any event from a machine or IP already in the chain (e.g. a second account used from the attacker's machine).
3. **Apply the gap rule.** Sort the chain by time and walk back from detection. Stop at the first silence longer than `max_gap_days` (**180**); everything before that gap is dropped as unrelated history.
4. **Pick the three start points:**

| Option | Start point | Meaning |
|---|---|---|
| **Aggressive** | First **strong** event in the chain | The latest restore point that still excludes every strongly flagged file |
| **Recommended** | First **medium or strong** event in the chain | The attacker's first trace (identity new to the volume, or strong evidence) |
| **Cautious** | Recommended start, or the first time any chain IP or machine was seen on **any** volume, whichever is earlier, minus `cautious_margin_hours` (**24**) | Covers reconnaissance on other shares and clock uncertainty |

5. **Snap to snapshots.** Each restore time = the **latest snapshot strictly before** its start point. Lab: 5-minute boundaries from the simulated epoch.
6. **Report impact per option:**
   - suspicious files (score ≥ `min_score`) that fall **inside** the resulting review window;
   - strongly flagged files that would fall **before** it, so they would survive the restore without being reviewed (should be 0 for recommended and aggressive);
   - the evidence chain: the events that set the start point, with their rule IDs.
7. **If no option exists** (the chain is empty, or it has only weak events): return `insufficient_evidence`; the admin must enter a restore time manually. Weak-only chains are listed as information.

Strong events **not** linked to the chain (e.g. a legitimate user saving a macro document) never move the suggestion. They are listed separately under "other suspicious activity in the lookback".

### Configuration: `specs/config/restore_suggest.toml`

```toml
version = "1.0"
lookback_days = 365              # how far back the engine looks for the attacker's trace
max_gap_days = 180               # a silence longer than this ends the chain
cautious_margin_hours = 24
snapshot_interval_minutes = 5    # lab only; the product uses the real snapshot list
strong_rules = ["FEED-MATCH", "R-W2", "R-W4", "R-W5", "R-W6", "S-AV"]
link_by_hash = true
link_by_machine_or_ip = true
```

### Requirements

| ID | Requirement |
|---|---|
| RT-01 | When an incident arrives **without** a restore time, B10 MUST compute a suggestion before entering `awaiting_restore_time`, and attach it to the incident. When the incident already has a restore time (e.g. from a scenario), the suggestion is still computed and stored for comparison. |
| RT-02 | The suggestion MUST follow the procedure above exactly. It reads **only the ledger**: zero content reads (RB-R3). |
| RT-03 | The output MUST include, per option: restore time, start point, the evidence events (artifact IDs, paths, rule IDs, identity, time), and the impact counts from step 6. |
| RT-04 | Suggest only: the engine MUST NOT set the restore time. The admin accepts with `dwta-incident set-restore-time <id> recommended|cautious|aggressive` or enters any time as today. The chosen option, or "manual", is recorded on the incident. |
| RT-05 | Suggestions MUST be snapshot-aligned (step 5). Manually entered times are accepted as entered. |
| RT-06 | Deterministic: the same ledger state, incident and configuration give a byte-identical suggestion. It records the configuration version and SHA-256. |
| RT-07 | `dwta-incident suggest <id>` recomputes and prints the suggestion at any time before finalize. |
| RT-08 | Performance: a suggestion over 1 M artifacts completes in under 2 s (indexed queries on identity and time). |

### Data contract: `run/incidents/<id>/restore-suggestion.json` (`dwta.restore_suggestion/v1`)

```json
{"schema":"dwta.restore_suggestion/v1","incident_id":"inc-…","detected_sim_ts":"2026-11-08T02:05:00Z",
 "config":{"version":"1.0","sha256":"…"},"status":"ok",
 "options":{
  "aggressive": {"start":"2026-11-02T09:14:00Z","restore_time":"2026-11-02T09:10:00Z",
                 "evidence":[{"artifact_id":54,"path":"/Q3/Q3-Report.pdf","rules":["R-W2","FEED-MATCH"],
                              "identity":{"user":"svc-backup","ip":"10.250.1.66","machine":"SRV-BKP01"}}],
                 "impact":{"suspicious_in_window":2,"strong_before_window":0}},
  "recommended": {"start":"2026-11-02T09:14:00Z","restore_time":"2026-11-02T09:10:00Z","evidence":["…"],"impact":{"…":0}},
  "cautious":    {"start":"2026-11-01T09:14:00Z","restore_time":"2026-11-01T09:10:00Z","evidence":["…"],"impact":{"…":0}}},
 "chain":{"events":43,"first":"2026-11-02T09:14:00Z","identities":{"users":["svc-backup"],"ips":["10.250.1.66"],"machines":["SRV-BKP01"]}},
 "other_suspicious":[]}
```

Ledger addition: `incidents.restore_suggestion JSONB`, `incidents.restore_time_source TEXT` (`recommended` | `cautious` | `aggressive` | `manual` | `scenario`).

### Acceptance scenarios

All use harmless artifacts and the simulated clock.

- **RT-AT-01 – Dwell-window demo.** *When* `dwell-window` runs **without** a restore time in `raise_incident`, *then* the start point for recommended and aggressive is the plant at D1 09:14, both restore times are **D1 09:10**, and `strong_before_window = 0`.
- **RT-AT-02 – Against ground truth.** *For* every scenario run, the recommended restore time is **at or before** the simulator's first malicious operation, and no more than one snapshot interval (5 minutes) earlier.
- **RT-AT-03 – Unrelated suspicious file.** *Given* `jdoe` saves an auto-running macro document on D3, *then* the suggestion does not move, and the file is listed under `other_suspicious`.
- **RT-AT-04 – Gap rule.** *Given* `SRV-BKP01` wrote one file 200 days before detection and nothing until D1, *then* that write is excluded (silence > 180 days) and the recommended start stays at D1 09:14.
- **RT-AT-05 – Stolen credentials.** *Given* the attacker logs in as the established user `jdoe` from `SRV-BKP01`, *then* `jdoe`'s routine writes are weak, the chain grows through the machine, and the recommended start is the first write from `SRV-BKP01`, not `jdoe`'s first-ever edit.
- **RT-AT-06 – Same payload elsewhere.** *Given* the same benign PE is copied to `software` from another IP on D3, *then* it joins the chain by hash, and that IP's earlier writes are considered.
- **RT-AT-07 – No evidence.** *Given* the incident identity has no writes in the lookback, *then* `status = insufficient_evidence` and the incident waits for a manual restore time.
- **RT-AT-08 – Admin choice recorded.** `set-restore-time <id> recommended` sets the restore time from the suggestion and records `restore_time_source = recommended`; a manual time records `manual`.
- **RT-AT-09 – No reads.** Computing a suggestion reads zero bytes of file content.

### Known limits

- **RT-G1 – Established identities.** An attacker who only ever uses a long-established account from a long-established machine produces weak evidence only, so there's no suggestion until a strong signal appears. A per-identity behavior baseline (BL-07) would close this.
- **RT-G2 – Starts at the first trace on the share.** Activity the attacker performed elsewhere (other systems, reads, which aren't audited, D-04) is invisible; the cautious margin is the mitigation.
- **RT-G3 – Snapshot availability.** In the product, the snapped restore time must be an existing, unexpired snapshot; if the right snapshot has expired, the engine must say so instead of silently picking a later one.

### Open questions

1. **Window cap vs lookback:** `ranking.toml` caps the review window at `max_window_days = 90`, while this feature looks back 365 days with a 180-day gap rule. Raise the cap to 365, or cap the suggestion at 90 and warn?
2. **Product snapshot list:** which API or source gives the Edge/NMC snapshot times per volume, and how long are they retained?
3. **Should the admin see the suggestion's evidence chain in full** in the review UI, or only the start event?
4. **Scenario support:** should `raise_incident` accept `restore_time = "suggested"` so demos use the suggestion end to end?

### Implementation mapping (when approved)

| Part | Where |
|---|---|
| Suggestion engine | `services/incident/src/dwta_incident/suggest.py` (ledger queries only) |
| Config | `specs/config/restore_suggest.toml` |
| Ledger migration | `004_restore_suggestion.sql` (two `incidents` columns) |
| CLI | `dwta-incident suggest`; `set-restore-time … recommended|cautious|aggressive` |
| Contract | `specs/schemas/restore_suggestion.v1.schema.json` |
| Tests | Unit (procedure on fixed ledger fixtures), acceptance RT-AT-01 to 09 (new catalog steps for RT-AT-03 to 06) |

### Implementation notes (Edge integration, 2026-11-04)

- **Where:** `unity/python3/dwta/src/dwta_incident/suggest.py`, config `specs/config/restore_suggest.toml`, ledger migration `006_restore_suggestion.sql` (`incidents.restore_suggestion`, `incidents.restore_time_source`). In the Edge integration the "restore time" of this spec is the **lookback start** (the review window start); the restore point itself stays Ransomware Protection's snapshot.
- **Contract:** `DwtaIncident.lookback_suggestion` (recommended / cautious / aggressive, each with `lookback_start`, plain-language `rationale`, `evidence`, `flagged_in_window`, `strong_before_window`, `capped`) and `lookback_source`; `DwtaStartReviewCommand.lookback_source`.
- **Portal:** the lookback form shows how the suggestion was worked out, the three options with their reasoning and impact, the evidence chain, and **"Your own time"**. Selecting an option fills the date field; editing the date makes it the admin's own time (any time before detection). The choice is recorded (`recommended` / `cautious` / `aggressive` / `manual`).
- **Answers to the open questions:**
  1. The suggestion looks back 365 days but each option is capped at the 90-day review window (`capped: true` and a note in the rationale).
  2. Product snapshot list: not used yet; options snap to the 5-minute grid on the simulated clock (lab mode).
  3. The UI shows the start event plus up to five linked writes, and other flagged files not linked to the attacker.
  4. Not needed: the filer scenario raises a real RP incident and the suggestion is computed for it.
- **Addition:** an IP address or computer name used by `shared_identity_accounts` (3) or more accounts in the lookback is treated as shared (NAT gateway, VDI, jump host) and is neither matched against the incident nor used to grow the chain. Without it, every lab client (all behind Docker NAT) would look like the attacker.
- **Verified (RT-AT-01):** on the lab Edge, recommended and aggressive start at the plant (D1 09:14), lookback start D1 09:10, `strong_before_window = 0`; deterministic across runs.

