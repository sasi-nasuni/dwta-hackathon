"""Ransomware actions: encrypt (reversible) and drop_note. Limited to seeded files only (SIM-07)."""

from __future__ import annotations

import fnmatch
import hashlib
import time

from .. import keystream
from ..scenario import Step
from ..smb import SmbSession as S
from . import _require_share, action

NOTE = (b"DwTA LAB TEST NOTE\r\nThis is a harmless note written by the DwTA attack simulator.\r\n"
        b"No data was harmed. Restore with: dwta-sim restore <run_id>\r\n")


@action("encrypt", validate=_require_share)
def encrypt(ctx, step: Step) -> None:
    share = step.params["share"]
    pattern = step.params.get("paths", "*")
    suffix = step.params.get("suffix", ".dwtalocked")
    rate = max(1, int(step.params.get("rate", 20)))
    targets = [f for f in ctx.seeded(share) if fnmatch.fnmatch(f["path"], pattern)]  # seeded files only (SIM-07)
    sess = ctx.session(step)
    folders: set[str] = set()
    for i in range(0, len(targets), rate):
        t0 = time.monotonic()
        batch = targets[i: i + rate]
        names = {f["path"]: f"enc-{step.index}-{i + j}" for j, f in enumerate(batch)}
        sess.run(share, [S.get(f["path"], f"{ctx.staging_container}/{names[f['path']]}.in") for f in batch])
        cmds, recs = [], []
        for f in batch:
            plain = ctx.staged_bytes(f"{names[f['path']]}.in")
            locked = keystream.transform(plain, ctx.key, f"{share}{f['path']}")
            staged = ctx.stage(f"{names[f['path']]}.out", locked)
            dst = f["path"] + suffix
            cmds += [S.put(staged, dst), S.delete(f["path"])]
            recs.append((f, dst, hashlib.sha256(locked).hexdigest()))
            folders.add(f["path"].rsplit("/", 1)[0] or "/")
        sess.run(share, cmds)
        for f, dst, sha in recs:
            ctx.truth(step, op="write", share=share, path=dst, sha256=sha, expected_event="write_close",
                      encrypted_from=f["path"])
            ctx.truth(step, op="delete", share=share, path=f["path"], expected_event="delete")
        elapsed = time.monotonic() - t0
        if i + rate < len(targets) and elapsed < 1.0:
            time.sleep(1.0 - elapsed)
    ctx.step_facts[step.id or f"#{step.index}"] = {"share": share, "folders": sorted(folders),
                                                     "count": len(targets), "suffix": suffix}
    if step.params.get("note", True):
        staged = ctx.stage(f"note-{step.index}.txt", NOTE)
        name = step.params.get("note_name", "README-DWTA-TEST.txt")
        paths = [f"{d.rstrip('/')}/{name}" for d in sorted(folders)]
        sess.run(share, [S.put(staged, p) for p in paths])
        for p in paths:
            ctx.truth(step, op="write", share=share, path=p, sha256=hashlib.sha256(NOTE).hexdigest(),
                      expected_event="write_close", ransom_note=True)
