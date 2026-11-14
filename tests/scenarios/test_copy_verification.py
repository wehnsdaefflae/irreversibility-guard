"""I1b — copy tracking is VERIFIED against storage, not inferred from a copy act.

Until 2026-11-14 `guard/taint.py` cleared clause 3 of the taint closure ("no other
location holds this content") from structural bookkeeping alone: a copy counted as a
surviving copy because a copy-style act had been ALLOWED, forever, even if a process
outside the guard had since deleted it. That is an UNDER-block — the only failure mode
in the module that loses content rather than annoying a user — and it was stated as a
limitation in LIMITATIONS.md rather than fixed.

The fix is an interface, not a heuristic: the integration supplies an `existence_probe`,
because only the integration can see the storage the guard reasons about, and
`Policy.copy_verification` says how a believed copy becomes one that may be relied on.
Everything that is not a positive confirmation — no probe, None, a raise — fails closed.

`test_the_under_block_the_fix_closes` holds the pre-fix behaviour as `"trust"` so the
difference is MEASURED rather than asserted, exactly as `composition="table"` keeps the
old pair table reachable as a baseline.
"""
import pytest

from guard.classifier import REVERSIBLE, ManifestEntry, default_classifier
from guard.core import Action
from guard.policy import Dial, Guard, Policy
from guard.taint import (ASSUME_COPIES_ABSENT, COPY_VERIFICATIONS, PROBE_COPIES,
                         TRUST_COPIES, TaintState)


def _raises(_loc):
    raise OSError("the object store is unreachable")


def _snapshot_world(copy_verification=PROBE_COPIES, existence_probe=None):
    """A DB whose drop is declared reversible *because a snapshot restores it*.

    This is the shape in which the bug actually loses data. A bare `fs:delete` is
    declared irreversible and is held by the ordinary gates whatever the copy tracking
    says, so it cannot show the difference; a verb whose declared undo IS the copy can.
    """
    c = default_classifier()
    c.declare("db:snapshot",
              ManifestEntry(REVERSIBLE, undo="delete the snapshot", effect="create"))
    c.declare("db:drop_table",
              ManifestEntry(REVERSIBLE, undo="restore from the snapshot", effect="destroy"))
    p = Policy(dial=Dial.HOLD_IRREVERSIBLE, copy_verification=copy_verification,
               existence_probe=existence_probe)
    p.grant("db:snapshot")
    p.grant("db:drop_table")
    g = Guard(policy=p, classifier=c)
    g.taint.declare_preexisting("db:prod.users")
    return g


def _snapshot_then_drop(g):
    snap = g.check(Action("db", "snapshot", "s3:snap/users", {"source": "db:prod.users"}))
    drop = g.check(Action("db", "drop_table", "db:prod.users", {}))
    return snap, drop


# ---------------------------------------------------------------- the fix

def test_the_under_block_the_fix_closes():
    """The pre-2026-11-14 behaviour, kept reachable as the measured baseline.

    `trust` ALLOWS dropping a production table whose only snapshot a process outside the
    guard has already deleted. Nothing in the module can tell, because nothing asks.
    """
    snap, drop = _snapshot_then_drop(_snapshot_world(copy_verification=TRUST_COPIES,
                                                     existence_probe=lambda _loc: False))
    assert snap.verdict.name == "ALLOW"
    assert drop.verdict.name == "ALLOW"          # <- the under-block, reproduced
    assert drop.reason == "allow.reversible"


def test_a_copy_the_probe_says_is_gone_no_longer_counts():
    snap, drop = _snapshot_then_drop(_snapshot_world(existence_probe=lambda _loc: False))
    assert snap.verdict.name == "ALLOW"
    assert drop.verdict.name == "REQUIRE_HUMAN"
    assert drop.reason == "require_human.reversible_steps_compose_irreversibly"
    assert "unverified" in drop.evidence["composition"]


def test_a_confirmed_copy_still_counts_so_the_fix_is_not_a_blanket_block():
    """The fix must not simply block everything: a verified backup still clears clause 3."""
    snap, drop = _snapshot_then_drop(_snapshot_world(existence_probe=lambda _loc: True))
    assert snap.verdict.name == "ALLOW"
    assert drop.verdict.name == "ALLOW"
    assert drop.reason == "allow.reversible"


def test_no_probe_supplied_fails_closed_rather_than_trusting():
    """The default for an integration that declares nothing is the SAFE reading."""
    _snap, drop = _snapshot_then_drop(_snapshot_world(existence_probe=None))
    assert Policy().copy_verification == PROBE_COPIES
    assert drop.verdict.name == "REQUIRE_HUMAN"


def test_a_raising_probe_is_unknown_not_evidence_of_existence():
    g = _snapshot_world(existence_probe=_raises)
    _snap, drop = _snapshot_then_drop(g)
    assert drop.verdict.name == "REQUIRE_HUMAN"
    assert g.taint.probe_errors == 1


def test_a_probe_returning_none_is_unknown():
    _snap, drop = _snapshot_then_drop(_snapshot_world(existence_probe=lambda _loc: None))
    assert drop.verdict.name == "REQUIRE_HUMAN"


def test_assume_absent_ignores_even_a_confirming_probe():
    _snap, drop = _snapshot_then_drop(
        _snapshot_world(copy_verification=ASSUME_COPIES_ABSENT,
                        existence_probe=lambda _loc: True))
    assert drop.verdict.name == "REQUIRE_HUMAN"


# ---------------------------------------------------------------- the surface

def test_a_misspelled_mode_is_refused_loudly():
    """A typo must not silently select the trusting path."""
    with pytest.raises(ValueError) as exc:
        TaintState(copy_verification="trusted")
    assert "copy_verification" in str(exc.value)
    assert set(COPY_VERIFICATIONS) == {TRUST_COPIES, PROBE_COPIES, ASSUME_COPIES_ABSENT}


def test_the_policy_dial_reaches_the_taint_state():
    g = _snapshot_world(copy_verification=ASSUME_COPIES_ABSENT)
    assert g.taint.copy_verification == ASSUME_COPIES_ABSENT


def test_copies_of_still_reports_what_is_BELIEVED():
    """The structural question is still answerable — it just no longer decides."""
    t = TaintState(copy_verification=PROBE_COPIES, existence_probe=lambda _loc: False)
    t.declare_preexisting("/data/a")
    t.record(Action("fs", "copy", "/backup/a", {"source": "/data/a"}), "create")
    assert t.copies_of("/data/a") == {"/backup/a"}       # believed
    assert t.surviving_copies("/data/a") == set()        # and not relied upon
    assert t.unverified_copies == {"/backup/a"}


def test_the_probe_is_asked_about_the_copy_not_the_target():
    asked = []
    t = TaintState(copy_verification=PROBE_COPIES,
                   existence_probe=lambda loc: asked.append(loc) or True)
    t.declare_preexisting("/data/a")
    t.record(Action("fs", "copy", "/backup/a", {"source": "/data/a"}), "create")
    assert t.surviving_copies("/data/a") == {"/backup/a"}
    assert asked == ["/backup/a"]


def test_an_agent_authored_target_is_unaffected_by_copy_verification():
    """Clause 2 short-circuits before clause 3: the agent can re-author its own content.

    Asserted on the derivation rather than through `Guard.check`, because a destroy of
    agent-authored content is held or denied by the ordinary gates (no declared undo
    path) whatever the copy tracking says — so a verdict could not show whether clause 3
    was consulted at all. `composite_risk` can.
    """
    t = TaintState(copy_verification=ASSUME_COPIES_ABSENT)
    t.record(Action("fs", "write_new", "/scratch/mine", {}), "create")
    assert t.at["/scratch/mine"].provenance == "agent"
    assert t.composite_risk(Action("fs", "truncate", "/scratch/mine", {}), "destroy") == ""


def test_the_strictest_mode_does_not_fire_on_an_untouched_location():
    """And it must not fire where the session did nothing: clause 1/4 still bound it."""
    t = TaintState(copy_verification=ASSUME_COPIES_ABSENT)
    t.declare_preexisting("/data/untouched")
    assert t.composite_risk(Action("fs", "truncate", "/data/untouched", {}), "destroy") == ""
