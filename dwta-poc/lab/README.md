# lab/

Runtime state for lab instances. Everything here except this file is git-ignored.

```
lab/
  corpus/<pack-id>/            corpus packs built by `dwta-sim corpus build`
  <INSTANCE>/
    .env                       ports, subnet, generated secrets (mode 600)
    secrets/                   per-identity smbclient auth files
    data/{finance,software}/   share contents (Samba bind mount)
    logs/audit.log             Samba vfs_full_audit output
    run/                       journal/, simclock.json, runs/<run_id>/, alerts.jsonl, incidents/
    feeds/{inbox,processed,rejected}/
    incidents/{inbox,rejected}/
```
