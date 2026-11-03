# DwTA POC — Dwell-Window Threat Assurance

**Core idea.** When a ransomware incident is detected, the admin gives a **restore time**. *Before* restoring, DwTA lists the
files written since then that look suspicious, each with a **suspicion score and level** and the reasons. The admin marks
each one **remove** or **keep**, and the restore runs **without the removed files**. Dormant files the attacker planted
therefore can't survive the recovery to be reused in a later attack.

Specification: [`../DwTA-Spec-v1.ipynb`](../DwTA-Spec-v1.ipynb) (v1.0). Implementation notes and deviations:
[`docs/implementation-notes.md`](docs/implementation-notes.md).

---

## Repository layout

A **uv workspace monorepo**. Every deployable is its own Python distribution with a `src/` layout and its own tests.
Contracts and configuration live in `specs/`; container and Compose files in `deploy/`.

```
dwta-poc/
├── pyproject.toml            workspace root: members, dev tools (pytest, ruff), shared tool config
├── uv.lock                   locked dependency graph for the whole workspace
├── Makefile                  developer entry points (setup, test, acceptance, lab-*, demo, review)
│
├── packages/                 shared libraries (imported, never deployed alone)
│   ├── dwta-core/            stdlib-only: fs_event contract, simulated clock, event journal, config loader, logging
│   └── dwta-ledger/          Postgres access: SQL migrations, per-service roles, alerts/offset helpers  [dwta-ledger]
│
├── services/                 one deployable service per block (one container image each)
│   ├── collector/            B4  Samba audit tailer + file watcher -> fs_event journal          [dwta-collector]
│   ├── classifier/           B5  single content pass, rules + Magika typing, oletools, YARA-X  [dwta-classifier]
│   ├── matcher/              B8  threat feed inbox -> hash lookup in the ledger                  [dwta-matcher]
│   └── incident/             B9/B10 incident intake + pre-restore review engine + admin CLI      [dwta-incident]
│
├── tools/
│   └── dwta-sim/             B3  host-side CLIs (stdlib only): attack simulator + lab manager    [dwta-sim, dwta-lab]
│
├── specs/                    contracts and configuration: the source of truth, never hard-coded
│   ├── schemas/              JSON Schemas: fs_event, groundtruth, incident, review_list, restore_exclusions
│   ├── config/               lab, magic, ext_map, magika_map, rules, ranking, attack_outputs, read_budget (TOML)
│   └── yara/                 YARA-X rules
│
├── scenarios/                attack scenarios (TOML), e.g. dwell-window.toml
├── deploy/
│   ├── compose/              docker-compose.yml (all values from lab/<instance>/.env)
│   └── images/               samba/ (B2), smbclient/ (B1), python-service/ (one multi-target Dockerfile)
├── tests/
│   ├── contract/             lab output validates against specs/schemas
│   └── acceptance/           end-to-end dwell-window story on a throwaway lab instance
├── docs/                     implementation notes
└── lab/                      runtime state per instance (git-ignored): data, logs, journal, feeds, incidents, secrets
```

| Distribution | Path | Console scripts | Container image | Block |
|---|---|---|---|---|
| `dwta-core` | `packages/dwta-core` | — | (in every image) | shared |
| `dwta-ledger` | `packages/dwta-ledger` | `dwta-ledger` | `dwta-ledger-migrate` | B6 |
| `dwta-collector` | `services/collector` | `dwta-collector` | `dwta-collector` | B4 |
| `dwta-classifier` (+ `[ai]` = Magika) | `services/classifier` | `dwta-classifier` | `dwta-classifier` | B5 |
| `dwta-matcher` | `services/matcher` | `dwta-matcher` | `dwta-matcher` | B7/B8 |
| `dwta-incident` | `services/incident` | `dwta-incident` | `dwta-incident` | B9/B10 |
| `dwta-sim` | `tools/dwta-sim` | `dwta-sim`, `dwta-lab` | — (runs on the Mac) | B1/B3 |
| — | `deploy/images/samba` | — | `dwta-samba` | B2 |
| — | `deploy/images/smbclient` | — | `dwta-smbclient` | B1 |

---

## Quickstart (reference Mac: Apple Silicon, Docker Desktop, uv)

```bash
make setup        # uv sync: one .venv with every package + pytest/ruff
make test         # unit tests, no Docker
make lab-up       # dwta-lab init + build images + start 11 containers (instance dwta1)
make demo         # build the corpus pack once, then run the dwell-window scenario (~7 s)
make review       # show the pre-restore review list of the latest incident
```

Admin flow on the incident the scenario raised:

```bash
I=$(ls -t lab/dwta1/run/incidents | head -1)
X="uv run dwta-lab compose exec -T incident dwta-incident"
$X show $I                         # ranked suspicious files with level, score, reasons
$X show $I --mode rules_ai         # same review with Magika as the primary typer
$X decide $I 1 remove --by admin   # keep rank 1 out of the recovery
$X decide $I 2 remove --by admin
$X finalize $I --by admin          # refused while anything is pending; writes the manifest
cat lab/dwta1/run/incidents/$I/restore-exclusions.json
uv run dwta-sim restore <run_id>   # Targeted Restore stand-in: encrypted files come back, planted files stay
```

Two-stage incident, like the product (detector first, admin's restore time later):

```bash
$X raise --id inc-1 --detected "D9 08:00" --user svc-backup --ip 10.250.1.66 --machine SRV-BKP01 --volume finance
$X set-restore-time inc-1 "D8 00:00"
```

Mount a share from Finder or the shell (custom port, never 445): `smb://jdoe@127.0.0.1:<SMB_PORT>/finance`
(the port and passwords are in `lab/dwta1/.env`).

## Tests

| Command | What | Needs |
|---|---|---|
| `make test` | unit tests: journal, clock, collector correlation/replay/restart, typers, rules, read budget, engine scoring, feed parser + contract tests | nothing |
| `make acceptance` | the full Day 1 / 5 / 7 story + decisions + manifest + restore stand-in, on a throwaway instance `dwta-at` | Docker |
| `uv run dwta-sim score <run_id>` | collector output vs the run's ground truth (recall, duplicates, attribution) | running lab |
| `make lint` | ruff | nothing |

## Lab operations

`dwta-lab -i <instance> init | up | down [--volumes] | reset | status | logs [svc] | compose <args>`.
Each instance gets its own free SMB port (14450–14499), lab subnet (10.250.x.0/24), secrets and ledger volume, so several
labs run side by side.
