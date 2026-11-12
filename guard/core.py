"""Canonical action rendering and the decision record.

Policy is written against *the act*, not its phrasing: every proposed tool call is
rendered to one stable string before any rule sees it.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Sequence


class Verdict(IntEnum):
    """Ordered by strictness, so the strictest member of a batch is simply max()."""

    ALLOW = 0
    HOLD = 1            # suspended; the agent must re-consent carrying evidence
    REQUIRE_HUMAN = 2   # only a human go on this exact act unblocks it
    DENY = 3            # refused structurally; no re-consent path

    @property
    def blocked(self) -> bool:
        return self is not Verdict.ALLOW


def render_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, Mapping):
        return "{" + ",".join(f"{k}={render_value(value[k])}" for k in sorted(value)) + "}"
    if isinstance(value, (list, tuple, set)):
        items = sorted(value, key=repr) if isinstance(value, set) else value
        return "[" + ",".join(render_value(v) for v in items) + "]"
    return str(value)


@dataclass
class Action:
    """One proposed tool call, as the agent emitted it."""

    tool: str
    verb: str
    target: str = ""
    args: Mapping[str, Any] = field(default_factory=dict)
    # agent | human | tool_output (untrusted) | undeclared
    #
    # The default is "undeclared" ON PURPOSE. An integrator who never plumbs
    # provenance must not silently ASSERT that every call was agent-authored: that
    # assertion is what makes the untrusted-origin denial meaningful, and a default
    # of "agent" would hand it out for free to exactly the integration that cannot
    # back it. Undeclared provenance fails closed the way an unknown verb does --
    # see Policy.trust_undeclared_origin and R_UNDECLARED_ORIGIN in policy.py.
    origin: str = "undeclared"
    members: Sequence["Action"] = ()  # non-empty => this is a batch

    @property
    def qualified_verb(self) -> str:
        return f"{self.tool}:{self.verb}"

    @property
    def is_batch(self) -> bool:
        return bool(self.members)

    def canonical(self) -> str:
        """Stable one-line rendering. Independent of kwarg order; `_`-args are excluded."""
        if self.is_batch:
            inner = " ; ".join(m.canonical() for m in self.members)
            return f"batch[{inner}]"
        parts = [self.qualified_verb]
        if self.target:
            parts.append(self.target)
        parts.extend(
            f"{k}={render_value(self.args[k])}"
            for k in sorted(self.args)
            if not k.startswith("_")
        )
        return " ".join(parts)

    def replace(self, **kw) -> "Action":
        data = dict(
            tool=self.tool, verb=self.verb, target=self.target, args=dict(self.args),
            origin=self.origin, members=tuple(self.members),
        )
        data.update(kw)
        return Action(**data)


@dataclass
class Decision:
    """The structured record of one interception. The harness asserts on this."""

    canonical: str
    verb: str
    target: str
    verdict: Verdict
    reason: str                       # stable machine-readable reason code
    tier: str                         # manifest | heuristic | unknown | structural
    reversibility: str                # reversible | irreversible | unknown
    evidence: dict = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    def to_record(self) -> dict:
        return {
            "canonical": self.canonical,
            "verb": self.verb,
            "target": self.target,
            "verdict": self.verdict.name,
            "reason": self.reason,
            "tier": self.tier,
            "reversibility": self.reversibility,
            "evidence": self.evidence,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_record(), sort_keys=True)

    def __str__(self) -> str:  # pragma: no cover - diagnostics only
        return f"{self.verdict.name}({self.reason}) <- {self.canonical}"
