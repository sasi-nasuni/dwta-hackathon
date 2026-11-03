"""Action plug-ins (SIM-06). Each action registers itself; the runner never changes when one is added."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..context import RunContext
    from ..scenario import Step


@dataclass(frozen=True)
class ActionSpec:
    name: str
    run: Callable[[RunContext, Step], None]
    needs_actor: bool = True
    validate: Callable[[Step], None] = lambda step: None


REGISTRY: dict[str, ActionSpec] = {}


def action(name: str, needs_actor: bool = True, validate: Callable | None = None):
    def deco(fn):
        REGISTRY[name] = ActionSpec(name, fn, needs_actor, validate or (lambda step: None))
        return fn
    return deco


def _require_share(step: Step) -> None:
    from ..scenario import ScenarioError
    if "share" not in step.params:
        raise ScenarioError(f"step {step.index} ({step.action}): missing 'share'")


def load_all() -> dict[str, ActionSpec]:
    from . import files, intel, ransom  # noqa: F401  (registration side effects)
    return REGISTRY
