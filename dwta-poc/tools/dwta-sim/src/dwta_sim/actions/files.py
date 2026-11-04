"""File actions: seed, edit, write, plant, sleep."""

from __future__ import annotations

import fnmatch
import hashlib
import random

from .. import artifacts, corpus
from ..scenario import ScenarioError, Step
from ..smb import SmbSession as S
from . import action
from .ransom import _run_parallel


def _require(step: Step, *keys: str) -> None:
    missing = [k for k in keys if k not in step.params]
    if missing:
        raise ScenarioError(f"step {step.index} ({step.action}): missing {missing}")


@action("seed")
def seed(ctx, step: Step) -> None:
    """Upload the corpus pack (every share, or ``share``) as the step's actor."""
    shares = [step.params["share"]] if "share" in step.params else sorted({f["share"] for f in ctx.manifest["files"]})
    for share in shares:
        files = ctx.seeded(share)
        folders = sorted({f["path"].rsplit("/", 1)[0] for f in files if f["path"].count("/") > 1})
        sess = ctx.session(step)
        puts = [[S.put(ctx.corpus_container_path(share, f["src"]), f["path"])] for f in files]
        parallel = max(1, int(step.params.get("parallel", 1)))
        if parallel > 1:  # high-latency link to a real Edge: folders first, then the uploads over N sessions
            if folders:
                sess.run(share, [S.mkdir(d) for d in folders])
            _run_parallel(sess, share, puts, parallel)
        else:
            sess.run(share, [S.mkdir(d) for d in folders] + [c for g in puts for c in g])
        for d in folders:
            ctx.truth(step, op="mkdir", share=share, path=d, expected_event="mkdir")
        for f in files:
            ctx.truth(step, op="write", share=share, path=f["path"], sha256=f["sha256"], expected_event="write_close",
                      corpus_kind=f["kind"])


def _validate_edit(step: Step) -> None:
    _require(step, "share")
    if step.params.get("style", "office") not in ("office", "direct"):
        raise ScenarioError(f"step {step.index}: style must be office|direct")


@action("edit", validate=_validate_edit)
def edit(ctx, step: Step) -> None:
    """Legitimate-looking change to existing seeded documents: same type, new content."""
    share, count = step.params["share"], int(step.params.get("count", 1))
    pattern = step.params.get("paths", "*")
    style = step.params.get("style", "office")
    candidates = [f for f in ctx.seeded(share) if fnmatch.fnmatch(f["path"], pattern)
                  and f["kind"] in ("docx", "xlsx", "csv", "txt", "pdf")]
    rng = random.Random(f"{ctx.seed}:{step.index}:{step.at}:{step.actor}")
    chosen = rng.sample(candidates, min(count, len(candidates)))
    cmds, records = [], []
    for i, f in enumerate(chosen):
        data = corpus.make_file(f["kind"], rng)
        staged = ctx.stage(f"edit-{step.index}-{i}.{f['kind']}", data)
        sha = hashlib.sha256(data).hexdigest()
        if style == "office":
            folder = f["path"].rsplit("/", 1)[0]
            tmp = f"{folder}/~WRL{rng.randint(1000, 9999)}.tmp"
            cmds += [S.put(staged, tmp), S.rename(tmp, f["path"], replace=True)]
            records.append(dict(op="write", share=share, path=f["path"], prev_path=tmp, sha256=sha,
                                expected_event="write_close", via_rename=True))
        else:
            cmds.append(S.put(staged, f["path"]))
            records.append(dict(op="write", share=share, path=f["path"], sha256=sha, expected_event="write_close"))
    if cmds:
        ctx.session(step).run(share, cmds)
    for r in records:
        ctx.truth(step, **r)


@action("write", validate=lambda s: _require(s, "share", "path"))
def write(ctx, step: Step) -> None:
    share, path = step.params["share"], step.params["path"]
    if "artifact" in step.params:
        data, art = artifacts.get(step.params["artifact"]), step.params["artifact"]
    else:
        data, art = corpus.make_file(step.params.get("kind", "txt"), random.Random(f"{ctx.seed}:{step.index}")), None
    staged = ctx.stage(f"write-{step.index}", data)
    ctx.session(step).run(share, [S.put(staged, path)])
    ctx.truth(step, op="write", share=share, path=path, artifact=art, sha256=hashlib.sha256(data).hexdigest(),
              expected_event="write_close")


@action("plant", validate=lambda s: _require(s, "share", "path", "artifact"))
def plant(ctx, step: Step) -> None:
    """Approved safe artifact under a (possibly disguised) name. ``{random}`` in ``path`` becomes a realistic
    document-style stem picked per run (e.g. "/Q3/{random}.pdf" -> "/Q3/Contoso-Invoice-v2.pdf")."""
    share, path, art = step.params["share"], step.params["path"], step.params["artifact"]
    if "{random}" in path:
        rng = random.Random(f"plant:{ctx.run_id}:{step.index}")
        ext = path.rsplit(".", 1)[1] if "." in path.rsplit("/", 1)[-1] else "pdf"
        existing = {f["path"].lower() for f in ctx.seeded(share)}
        while True:
            candidate = path.replace("{random}", corpus.random_stem(ext, rng))
            if candidate.lower() not in existing:
                path = candidate
                break
    data = artifacts.get(art)
    staged = ctx.stage(f"plant-{step.index}", data)
    folder = path.rsplit("/", 1)[0]
    cmds = ([S.mkdir(folder)] if folder else []) + [S.put(staged, path)]
    ctx.session(step).run(share, cmds)
    ctx.truth(step, op="write", share=share, path=path, artifact=art, sha256=hashlib.sha256(data).hexdigest(),
              expected_event="write_close")
    ctx.step_facts[step.id or f"#{step.index}"] = {"share": share, "path": path}


@action("sleep", needs_actor=False)
def sleep(ctx, step: Step) -> None:
    """Advance the simulated clock only."""
