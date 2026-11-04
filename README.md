# DwTA: Dwell-Window Threat Assurance (hackathon)

Ransomware attackers often plant files days before they encrypt anything. Antivirus checks a file once, when nothing
knows it yet; behavior-based ransomware detection only sees the encryption burst; and Targeted Restore rolls back the
encrypted files but leaves the planted ones in place, ready for the next attack.

DwTA closes that gap: it records every written file by content (type, hash, macros, YARA) and context (who, from where,
previous version), re-checks the past by hash lookup when threat intelligence catches up, and, **before a restore**,
gives the admin a ranked, explained list of suspicious files written since the chosen point to **remove** or **keep**.

| Path | What |
|---|---|
| [`DwTA-Spec-v1.ipynb`](DwTA-Spec-v1.ipynb) | Specification v1.0 (polished) |
| [`DwTA-Spec-v1-Foundation.ipynb`](DwTA-Spec-v1-Foundation.ipynb) | Working draft with the full review history |
| [`DwTA-POC-Implementation-Plan-v0.2.md`](DwTA-POC-Implementation-Plan-v0.2.md) | Original POC plan (also as `.html`) |
| [`SPEC-read-budget-av-integration.md`](SPEC-read-budget-av-integration.md) | Read budget and antivirus integration |
| [`ransomware-protection-overview.md`](ransomware-protection-overview.md) | How the existing Ransomware Protection works |
| [`dwta-poc/`](dwta-poc/) | Implementation: Docker lab, simulator, collector, classifier, ledger, matcher, incident engine ([README](dwta-poc/README.md)) |

Quickstart (Apple Silicon Mac, Docker Desktop, [uv](https://docs.astral.sh/uv/)):

```bash
cd dwta-poc
make setup && make test     # unit + contract tests
make lab-up && make demo    # start the lab, run the dwell-window scenario
make review                 # the pre-restore review list
```

All test files are harmless: generated stubs, the EICAR test string, and a fabricated threat feed. No real malware.

## Product integration (Nasuni Edge, NBN daemon, Portal)

The integration of DwTA into the Nasuni product lives in the product repositories, on hackathon branches. They are
linked here as git submodules under [`Hackathon-POC/`](Hackathon-POC/), pinned to the integration commits. They are
private `nasuni` repositories, so the submodules are only readable with Nasuni GitHub access.

| Submodule | Branch | What |
|---|---|---|
| `Hackathon-POC/edge-api` | `dwta-hackathon` | DwTA commands/events in the Portal ↔ Edge contract |
| `Hackathon-POC/nbn-daemon` | `dwta-hackathon` | NBN daemon routes forwarding DwTA commands to the Edge |
| `Hackathon-POC/unity` | `dwta-hackathon` | Edge: audit tap, `dwtad` service, legacy routes, deploy scripts |
| `Hackathon-POC/portal` | `PORTAL-0000-dwta-hackathon` | Portal backend, event processors and the pre-restore review UI |

```bash
git submodule update --init   # needs access to github.com/nasuni
```

The simulator drives a real Edge with `dwta-sim -i filer run dwell-window-filer` (SMB clients run locally in Docker,
see [`deploy/compose/filer-clients.yml`](dwta-poc/deploy/compose/filer-clients.yml)).
