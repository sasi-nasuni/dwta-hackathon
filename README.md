# DwTA: Dwell-Window Threat Assurance (hackathon)

Ransomware attackers often plant files days before they encrypt anything. Antivirus checks a file once, when nothing
knows it yet; behavior-based ransomware detection only sees the encryption burst; and Targeted Restore rolls back the
encrypted files but leaves the planted ones in place, ready for the next attack.

DwTA closes that gap: it records every written file by content (type, hash, macros, YARA) and context (who, from where,
previous version), re-checks the past by hash lookup when threat intelligence catches up, and, **before a restore**,
gives the admin a ranked, explained list of suspicious files written since the chosen point to **remove** or **keep**.

| Path | What |
|---|---|
| [`spec/DwTA-Spec-v1.ipynb`](spec/DwTA-Spec-v1.ipynb) | Specification v1.0 |
| [`dwta-poc/`](dwta-poc/) | Lab implementation: Docker lab, simulator, collector, classifier, ledger, matcher, incident engine ([README](dwta-poc/README.md)) |
| [`Hackathon-POC/`](Hackathon-POC/) | Product integration: Nasuni Edge (Unity), NBN daemon, edge-api contract, Portal (git submodules, see below) |

Lab quickstart (Apple Silicon Mac, Docker Desktop, [uv](https://docs.astral.sh/uv/)):

```bash
cd dwta-poc
make setup && make test     # unit + contract tests
make lab-up && make demo    # start the lab, run the dwell-window scenario
make review                 # the pre-restore review list
```

All test files are harmless: generated stubs, the EICAR test string, and a fabricated threat feed. No real malware.

## Product integration (Nasuni Edge, NBN daemon, Portal)

DwTA also runs inside the Nasuni product: on a real Edge appliance, reached through the NBN daemon, with the review
in Portal under **Appliance Services → Ransomware Pre-Restore Review**. A real Ransomware Protection (RP) detection
starts it, and finalizing it starts RP's own Targeted Restore.

The code lives in the product repositories on hackathon branches, linked here as git submodules under
[`Hackathon-POC/`](Hackathon-POC/). They are private `nasuni` repositories: the submodules only resolve with Nasuni
GitHub access.

| Submodule | Branch | What |
|---|---|---|
| `Hackathon-POC/edge-api` | `dwta-hackathon` | DwTA commands and events in the Portal ↔ Edge contract (`edge-api-classic`) |
| `Hackathon-POC/nbn-daemon` | `dwta-hackathon` | NBN daemon routes that forward DwTA commands to the Edge and carry its events (RPM) |
| `Hackathon-POC/unity` | `dwta-hackathon` | Edge: audit tap, `dwtad` service, legacy routes, RP health, deploy and lab scripts |
| `Hackathon-POC/portal` | `PORTAL-0000-dwta-hackathon` | Portal: storage, event processors, API, and the review UI |

```bash
git submodule update --init   # needs access to github.com/nasuni
```

### Where things run

```
 Mac (Docker)                         Nasuni Edge (filer)                                   Portal (dev)
 ─────────────                        ───────────────────                                   ────────────
 dwta-sim + SMB client   ── SMB ──▶   Samba share ──▶ auditman ──┬──▶ antiransom (RP) ── incident ──┐
 containers (users,                                               │                                  │
 attacker)               ── SSH ──▶   sim clock,                  └──▶ dwta-tap ──▶ dwtad ◀──────────┘ polls RP
                                      threat feeds,                           │  ledger (local Postgres)
                                      snapshots                               │  classifier, matcher, review
                                                                              ▼
                                      filer-route-http (dwta.* routes) ◀── NBN daemon ◀── MQTT ──▶ eventhub
                                                                              │   send-event.py ──▶  → DB → webapi
                                                                              ▼                      → BFF → UI
                                      dwta-quarantine volume (no share)
```

- **Edge:** `dwta-tap` (Python 2) copies client file events (writes, renames, deletes, mkdirs and reads) from
  auditman, with the resolved user, client IP and share. `dwtad` (Python 3.11 venv at `/opt/nasuni/dwta`) runs these
  threads: source, classifier (rules + Magika + oletools + YARA-X), threat-feed matcher, RP bridge, RP-health
  publisher, and a loopback API used by the `dwta.*` legacy routes.
- **NBN daemon:** maps Portal commands to the `dwta.*` routes and validates the responses into events. Unsolicited
  events come from `send-event.py`.
- **Portal:** the eventhub stores the events (`dwta_incidents`, `dwta_rp_health`), the webapi and BFF serve
  `/v1/edges/{serial}/dwta/...`, and the frontend shows the review.
- **Mac:** the simulator plus SMB client containers act as normal users and an attacker against the Edge's share.

### End-to-end flow

1. **Attack.** Over SMB, the attacker reads existing files, writes `*.locked` copies in the same folders and
   deletes the originals.
2. **Detection.** RP scores 5-minute windows, reaches its incident level and creates an incident.
3. **New DwTA incident.** `dwtad` picks up the RP incident (`rp-<volume>-<id>`) and computes **lookback-start
   suggestions**. The portal gets `dwta.incident_detected`; Ransomware Protection notifications link straight to the
   incident.
4. **Lookback.** The admin chooses how far back to review: the recommended, cautious or aggressive suggestion
   (each with its reason and evidence), or a custom date and time.
5. **Review.** `dwtad` ranks every file written since then. It shows one list with a plain-language explanation per
   file, the file's audited activity, and dwell-window activity charts.
6. **Decide.** The admin marks each item **Remove** or **Keep** (auto-saved).
7. **Finalize & restore:**
   - every Remove file is copied to the **quarantine volume** and its SHA-256 verified;
   - the originals are deleted;
   - RP **Targeted Restore** rolls the attacked files back to the snapshot before the attack.

   Planted files are not brought back, and nothing is deleted outright.

### Features

**Edge (`dwtad`)**
- **Merged file type.** One content type per file from the file signature (magic bytes) and Magika (AI, used at
  ≥ 0.8 confidence), security-biased: a program or script verdict always wins. Otherwise the signature wins for
  formats with reliable headers and the AI for text-like content. The extension mismatch is judged against that
  type, and provenance (both / signature / AI / disagreement, plus confidence) is kept.
- **Ranking.** Signals: threat-feed hash match (also retroactive), program on a document share, extension
  mismatch, Office auto-run macros, YARA, type changed to a program, written by the attacker's account, IP or
  computer, and antivirus. The encrypted outputs are grouped into one item.
- **Plain-language reasons.** Each signal gets a title and a sentence built from its evidence (feed name and
  family, extension vs content, attacking account and IP, how the type was identified). No codes are shown to the
  admin.
- **Activity.** Per-file audited history (writes, renames, deletes, reads), combined activity for the
  encrypted-outputs group, and volume-wide activity buckets across the review window.
- **Lookback suggestion.** A rules-based engine that uses the ledger only:
  - it traces the incident's account, IP and computer back to their first trace and offers aggressive,
    recommended and cautious starts, snapped to snapshots;
  - shared IPs or computers (NAT, VDI) are ignored.
- **Quarantine volume.** Removed files go to a dedicated volume (`DWTA_QUARANTINE_VOLUME`, default
  `dwta-quarantine`). It has no share and RP is off on it. Files land under
  `/<volume>/<incident>/<path>` with a `manifest.json`, and are readable by root only. If the quarantine volume is
  missing or a copy fails, finalize is cancelled before anything changes.
- **RP health.** For every volume, the `dwta.rp.health` route reads antiransom's own per-day indicator maxima
  (today and yesterday). It maps them onto the Edge's anomaly thresholds (levels 0–5, Normal … Very High) and adds
  the incident and blocking levels, events processed and incident counts. `dwtad` sends this to Portal every
  5 minutes.

**Portal UI** (Appliance Services → Ransomware Pre-Restore Review)
- **Appliance list.** Online/Offline and version pills, recent ransomware risk (RP level), open incidents, last
  incident, RP-enabled volumes and blocked sources.
- **Per appliance.** Incidents table and a **Volume ransomware health** table (highest RP level today or
  yesterday per volume, top indicator, events, incidents, refresh).
- **Incident.**
  - An incident-details panel (attacker account and IP, volume, source, detection, restore point, lookback).
  - The lookback step with the suggestion cards, a timeline and a calendar picker.
  - The review table, one value per cell: score gauge, path, type with provenance hint, change, antivirus, and
    written by, from and at. It has search, filters and pagination, and header bulk select.
  - An item drawer with the plain-language reasons, file activity (CSV download) and Remove | Keep.
  - "File activity over time" charts, and a finalize-result panel (quarantine and Targeted Restore status).
- **Timestamps.** All use the shared `FormattedDate` with the user's portal timezone.
- **Notifications.** Ransomware Protection alerts link to the matching incident review.

### Interfaces

| Layer | DwTA surface |
|---|---|
| edge-api commands | `DwtaListIncidents`, `DwtaStartReview` (lookback + source), `DwtaGetReview`, `DwtaDecide`, `DwtaFinalize`, `DwtaInjectIncident`, `DwtaGetRpHealth` |
| edge-api events | `DwtaIncidentsListed`, `DwtaIncidentDetected`, `DwtaReview` (one `items` list + activity), `DwtaReviewFinalized`, `DwtaRpHealth` |
| NBN / legacy routes | `dwta.incidents.list`, `dwta.review.start/get/decide/finalize`, `dwta.incident.inject`, `dwta.rp.health`; filer-initiated `dwta.incident_detected`, `dwta.review_ready` |
| Portal API | `/v1/edges/{serial}/dwta/incidents[/refresh,/inject,/{id},/{id}/review[/refresh],/{id}/decisions,/{id}/finalize]`, `/v1/edges/{serial}/dwta/rp-health[/refresh]`, `/v1/dwta/rp-health`, `/v1/dwta/incidents/summary` |
| Portal DB | `dwta_incidents`, `dwta_rp_health` (Alembic migrations, row-level security like the rest of Portal) |

### Running it against an Edge

Prerequisites:
- an Edge registered to a Portal dev account, with Ransomware Protection licensed;
- SSH as root;
- cloud credentials on the Edge;
- Active Directory accounts for the simulated users;
- a local Portal (`make run` in the portal repo) whose eventhub reads your dev queues.

```bash
cd Hackathon-POC/unity
# deploy dwta-tap, dwtad (+ venv, Postgres DB) and the dwta.* routes; optionally the NBN daemon RPM
FILER=<edge-ip> PORT=<ssh-port> python3/dwta/deploy/deploy.sh [--nbnd-rpm ../nbn-daemon/dist/nasuni-nbnd-*.rpm]
# finance volume + share, RP policy, snapshot, quarantine volume, SMB credentials → dwta-poc/lab/filer/.env
FILER=<edge-ip> PORT=<ssh-port> python3/dwta/deploy/setup-lab-volume.sh
# once the Edge is joined to AD: NTFS policy on the volume, AD accounts for the simulator identities
FILER=<edge-ip> PORT=<ssh-port> SMB_DOMAIN=<NETBIOS> AD_ADMIN=... AD_PW_ADMIN=... python3/dwta/deploy/use-ad.sh

cd ../../dwta-poc
uv run dwta-sim -i filer run dwell-window-filer   # seeds, plants D1, threat feed D5, snapshot D6, encrypts D7
```

The run takes about 10 minutes. RP raises an incident, which appears in Portal waiting for a lookback start.
`lab-user-mode.sh` gives per-user SMB identities on an Edge without AD. **Inject demo incident** (or
`dwta-sim -i filer step raise_incident`) creates an incident without an attack, so there is no Targeted Restore.
Secrets stay in the git-ignored `dwta-poc/lab/filer/` folder.

### Ransomware Protection: what detects the attack

The simulated encryption matches RP's indicator *existing file read and deleted, then a new file with a known
ransomware extension (`*.locked`) written in the same folder*. RP counts these per user and client per 5-minute
window. For this indicator, levels 1–5 start at 20, 35, 50, 65 and 80 files. The scenario encrypts exactly 60
files, which is level 3: an incident, no blocking.

| Setting | Product default | This POC |
|---|---|---|
| Incident creation level | 3 (Medium) | 3 (Medium) |
| Blocking (mitigation) level | 4 (High), by username | 4 (High), by username |
| `ANTIRANSOM_CREATE_WINDOW`: when a file counts as "existing" | 2000 s | **60 s** (`/etc/nasuni/local.ini`) so the compressed scenario works; remove after the demo |
| Rollback | Never automatic: an admin starts Targeted Restore | Started by DwTA at **Finalize & restore**, after the review |

### Notes and limitations
- **Simulated clock.** The lab runs on a simulated clock (the dwell week is compressed into minutes), so detection
  times can read "in N days". On a real Edge they are wall-clock.
- **Quarantine is a copy.** Moving files to the quarantine volume is copy + verify + delete, not an atomic rename.
- **Antivirus.** The rescan is wired in but has no engine yet (`not_scanned`).
- **Internal notes.** The decision log, the RP comparison and the built wheels are kept off this public repository
  (see `.gitignore`).
