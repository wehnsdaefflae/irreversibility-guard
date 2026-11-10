"""The enforcement engine: capabilities, holds, preconditions, dials, composition.

Design rule throughout: the *structural* mechanisms (capability reservation per verb,
read-before-destroy preconditions, human-committed approval dials, composition
detection) do not consult the classifier's judgment about intent. They are sound.
The classifier only decides *whether an act is irreversible at all*, and when it
does not know, it fails closed.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

from .classifier import Classification, Classifier, default_classifier
from .core import Action, Decision, Verdict


class Dial(IntEnum):
    """Approval dial. At HUMAN_COMMITTED a self-modifying act is not agent-grantable."""

    PERMISSIVE = 0
    HOLD_IRREVERSIBLE = 1
    HUMAN_COMMITTED = 2


@dataclass
class Capability:
    """A grant on ONE qualified verb. `tool:*` grants the tool's reversible verbs only."""

    verb: str
    granted_by: str = "operator"


@dataclass
class Go:
    """A human go on ONE exact canonical act. Single-use, so a go cannot be replayed."""

    canonical: str
    by: str = "operator"
    used: bool = False


@dataclass
class Session:
    """What the agent has actually done, as evidence the structural gates consult."""

    reads: set[str] = field(default_factory=set)       # targets read in this session
    consented: set[str] = field(default_factory=set)   # canonical acts re-consented to
    gos: list[Go] = field(default_factory=list)
    effects: list[str] = field(default_factory=list)   # canonical acts performed
    tally: dict[str, int] = field(default_factory=dict)

    def record_read(self, target: str) -> None:
        self.reads.add(target)

    def grant_go(self, canonical: str, by: str = "operator") -> None:
        self.gos.append(Go(canonical, by))

    def take_go(self, canonical: str) -> Go | None:
        for go in self.gos:
            if go.canonical == canonical and not go.used:
                return go
        return None

    def note(self, label: str) -> None:
        self.tally[label] = self.tally.get(label, 0) + 1


# Reason codes. Stable: the scenario suite asserts on these.
R_ALLOW = "allow.reversible"
R_ALLOW_CONSENTED = "allow.re_consented"
R_ALLOW_GO = "allow.human_go"
R_NO_CAPABILITY = "deny.verb_not_granted"
R_UNKNOWN_VERB = "hold.unknown_verb_fails_closed"
R_HOLD_IRREVERSIBLE = "hold.irreversible_needs_reconsent"
R_NEEDS_READ = "deny.target_not_read_in_session"
R_NO_UNDO = "deny.no_undo_path_declared"
R_NEEDS_HUMAN = "require_human.outward_act"
R_SELF_MODIFY = "require_human.self_modifying_act"
R_SELF_MODIFY_DENIED = "deny.self_modifying_not_agent_grantable"
R_INJECTED_ORIGIN = "deny.instruction_from_untrusted_origin"
# verdict-neutral on purpose: a batch inherits the STRICTEST member's verdict, so this
# reason appears on HOLD, REQUIRE_HUMAN and DENY alike.
R_BATCH = "blocked.irreversible_member_in_batch"
R_COMPOSITION = "require_human.reversible_steps_compose_irreversibly"
R_RETRY = "hold.possible_duplicate_of_applied_act"
R_CONFLICT = "require_human.conflicting_constraints"


@dataclass
class Policy:
    dial: Dial = Dial.HOLD_IRREVERSIBLE
    capabilities: dict[str, Capability] = field(default_factory=dict)
    never: tuple[str, ...] = ()        # operator prohibitions, verb prefixes
    require_undo: bool = True
    read_before_destroy: bool = True

    def grant(self, verb: str, by: str = "operator") -> "Policy":
        self.capabilities[verb] = Capability(verb, by)
        return self

    def has_capability(self, qualified_verb: str, reversible: bool) -> bool:
        if qualified_verb in self.capabilities:
            return True
        tool = qualified_verb.split(":", 1)[0]
        # a wildcard grant covers the tool's REVERSIBLE verbs only: the outbound,
        # irreversible verb of an otherwise-granted tool stays reserved.
        return f"{tool}:*" in self.capabilities and reversible


# Composition rules: individually reversible steps whose sequence is not.
_COMPOSITIONS = (
    (("fs:truncate", "fs:write_new"), "truncate-then-write replaces content with no copy"),
    (("fs:append", "fs:truncate"), "append-then-truncate loses the appended content"),
    (("git:commit", "git:push"), "commit-then-push publishes irrevocably"),
    (("fs:write_new", "fs:delete"), "write-then-delete destroys the only copy"),
)


class Guard:
    """Sits between an agent and its tools. `check` is the whole public surface."""

    def __init__(
        self,
        policy: Policy | None = None,
        classifier: Classifier | None = None,
        audit_path: str | Path | None = None,
        session: Session | None = None,
    ) -> None:
        self.policy = policy or Policy()
        self.classifier = classifier or default_classifier()
        self.session = session or Session()
        self.audit_path = Path(audit_path) if audit_path else None
        self.decisions: list[Decision] = []

    # -- helpers ---------------------------------------------------------
    def _decide(self, action: Action, cls: Classification, verdict: Verdict,
                reason: str, **evidence) -> Decision:
        ev = {
            "reads_in_session": sorted(self.session.reads),
            "dial": self.policy.dial.name,
            "resolved_verb": cls.resolved_verb,
        }
        ev.update(evidence)
        decision = Decision(
            canonical=action.canonical(), verb=action.qualified_verb, target=action.target,
            verdict=verdict, reason=reason, tier=cls.tier,
            reversibility=cls.reversibility, evidence=ev,
        )
        self.decisions.append(decision)
        self.session.note(verdict.name)
        if self.audit_path:
            self.audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self.audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps({"ts": time.time(), **decision.to_record()}, sort_keys=True) + "\n")
        return decision

    def _composition_risk(self, action: Action) -> str:
        """Does this act complete a sequence whose composition is irreversible?"""
        history = list(self.session.effects)
        verb = action.qualified_verb
        for steps, why in _COMPOSITIONS:
            if verb != steps[-1]:
                continue
            need = list(steps[:-1])
            # the earlier steps must have happened, in order, on the same target
            idx = 0
            for done in history:
                if idx < len(need) and done.startswith(need[idx]) and action.target in done:
                    idx += 1
            if idx == len(need):
                return why
        return ""

    # -- the gate --------------------------------------------------------
    def check(self, action: Action, consent: bool = False) -> Decision:
        """Judge one proposed action. `consent=True` is the agent's re-consent."""
        cls = self.classifier.classify(action)

        # batch: judge members, surface the strictest. An irreversible act cannot
        # hide inside a batch of reversible ones.
        if action.is_batch:
            inner = [self.check(m, consent=consent) for m in action.members]
            worst = max(inner, key=lambda d: d.verdict)
            if worst.verdict is Verdict.ALLOW:
                return self._decide(action, cls, Verdict.ALLOW, R_ALLOW,
                                    members=[d.to_record() for d in inner])
            verdict = worst.verdict if worst.verdict > Verdict.HOLD else Verdict.HOLD
            return self._decide(action, cls, verdict, R_BATCH,
                                offending=worst.canonical, offending_reason=worst.reason,
                                members=[d.to_record() for d in inner])

        # an instruction that arrived in tool output / fetched content is not an
        # authority. Injection aimed at the guard dies here, before any policy read.
        if action.origin == "tool_output":
            return self._decide(action, cls, Verdict.DENY, R_INJECTED_ORIGIN,
                                origin=action.origin)

        # self-modifying acts: at the top dial they are not agent-grantable at all.
        if cls.entry is not None and cls.entry.self_modifying:
            if self.policy.dial is Dial.HUMAN_COMMITTED:
                return self._decide(action, cls, Verdict.DENY, R_SELF_MODIFY_DENIED)
            return self._decide(action, cls, Verdict.REQUIRE_HUMAN, R_SELF_MODIFY)

        # operator prohibition outranks the task.
        for prohibited in self.policy.never:
            if action.qualified_verb.startswith(prohibited):
                return self._decide(action, cls, Verdict.REQUIRE_HUMAN, R_CONFLICT,
                                    prohibition=prohibited)

        # capability, per VERB.
        if not self.policy.has_capability(action.qualified_verb,
                                          cls.reversibility == "reversible"):
            return self._decide(action, cls, Verdict.DENY, R_NO_CAPABILITY)

        if cls.tier == "unknown":
            return self._decide(action, cls, Verdict.HOLD, R_UNKNOWN_VERB)

        # Composition is checked for EVERY act, reversible or not: the dangerous case is
        # precisely a step that looks fine alone and completes an irreversible sequence.
        risk = self._composition_risk(action)
        if risk:
            return self._decide(action, cls, Verdict.REQUIRE_HUMAN, R_COMPOSITION,
                                composition=risk)

        if not cls.irreversible:
            if action.verb in ("read", "list", "get", "cat", "show"):
                self.session.record_read(action.target)
            self.session.effects.append(action.canonical())
            return self._decide(action, cls, Verdict.ALLOW, R_ALLOW)

        # ---- irreversible from here on ----
        entry = cls.entry

        # a blind retry of an act that may already have been applied
        if any(e == action.canonical() for e in self.session.effects):
            return self._decide(action, cls, Verdict.HOLD, R_RETRY,
                                already_applied=action.canonical())

        # read-before-destroy applies to acts that DESTROY CONTENT. An outward act's
        # target is a recipient or an endpoint, not something readable; requiring a
        # "read" of it would be meaningless, and the human-go gate below covers it.
        outward = entry is not None and entry.outward
        if (self.policy.read_before_destroy and not outward
                and action.target and action.target not in self.session.reads):
            return self._decide(action, cls, Verdict.DENY, R_NEEDS_READ)

        if self.policy.require_undo and entry is not None and not entry.undo and not entry.outward:
            # no declared undo path: only a human may authorise it
            if not self.session.take_go(action.canonical()):
                return self._decide(action, cls, Verdict.REQUIRE_HUMAN, R_NO_UNDO)

        if entry is not None and entry.outward:
            go = self.session.take_go(action.canonical())
            if go is None:
                return self._decide(action, cls, Verdict.REQUIRE_HUMAN, R_NEEDS_HUMAN)
            go.used = True
            self.session.effects.append(action.canonical())
            return self._decide(action, cls, Verdict.ALLOW, R_ALLOW_GO, go_by=go.by)

        go = self.session.take_go(action.canonical())
        if go is not None:
            go.used = True
            self.session.effects.append(action.canonical())
            return self._decide(action, cls, Verdict.ALLOW, R_ALLOW_GO, go_by=go.by)

        if self.policy.dial is Dial.PERMISSIVE:
            self.session.effects.append(action.canonical())
            return self._decide(action, cls, Verdict.ALLOW, R_ALLOW)

        if consent and action.canonical() in self.session.consented:
            self.session.effects.append(action.canonical())
            return self._decide(action, cls, Verdict.ALLOW, R_ALLOW_CONSENTED)

        self.session.consented.add(action.canonical())
        return self._decide(action, cls, Verdict.HOLD, R_HOLD_IRREVERSIBLE)
