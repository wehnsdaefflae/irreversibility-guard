"""bp-10 and the search property: compositions nobody declared.

Two things are asserted here.

1. **bp-10** — one concrete irreversible composition that the original four-row
   `policy._COMPOSITIONS` table does NOT contain, FOUND by `guard.search` rather than
   thought up by the author, and now blocked by the derived effect-taint closure. This
   is the case the search produced on 2026-11-11:

       fs:append /data/a  ;  fs:overwrite /data/a

   Each step is individually reversible by the manifest (append has an undo, overwrite
   replaces with agent-authored content), the pair is in no table, and together they
   destroy pre-existing content that nothing can reconstruct.

2. **The property itself** — in the DEPLOYABLE configuration (undo path required,
   read-before-destroy on) no sequence up to depth 3 both passes the guard entirely and
   loses pre-existing content, under a threat model where the agent re-consents to its
   own HOLDs. This is a regression property, not a discovery: it is currently vacuous in
   the sense that the ordinary gates stop these acts before composition is consulted,
   and the test says so, so a later relaxation of those gates fails here loudly.
"""
from __future__ import annotations

from guard import Action, Dial, Guard, Policy, Session, Verdict, default_classifier
from guard import policy as P
from guard.search import LOCATIONS, search, summarize


def _isolated_guard():
    """Composition isolated: the two gates that would otherwise pre-empt it are off."""
    pol = Policy(dial=Dial.HOLD_IRREVERSIBLE, require_undo=False, read_before_destroy=False)
    (pol.grant("fs:*").grant("fs:append").grant("fs:overwrite").grant("fs:truncate")
        .grant("fs:copy").grant("fs:delete").grant("fs:write_new"))
    g = Guard(policy=pol, classifier=default_classifier(), session=Session())
    g.taint.declare_preexisting("/data/a")
    return g


def test_bp_10_append_then_overwrite_is_derived_not_declared():
    g = _isolated_guard()
    assert g.check(Action("fs", "append", "/data/a")).verdict is Verdict.ALLOW
    d = g.check(Action("fs", "overwrite", "/data/a"))
    assert d.verdict is Verdict.REQUIRE_HUMAN, (
        f"bp-10: expected REQUIRE_HUMAN, got {d.verdict.name}/{d.reason}")
    assert d.reason == P.R_COMPOSITION, f"bp-10: wrong reason {d.reason}"
    assert "derived, not listed" in d.evidence["composition"]


def test_bp_11_copy_onto_an_occupied_path_is_not_the_reversible_act_it_declares():
    """A hazard the SEARCH found, not the author (2026-11-11).

    `fs:copy` is declared reversible with the undo "delete the copy" — true only of an
    empty target. Copying onto a location that already holds pre-existing content
    destroys it, and deleting the copy does not bring it back. 184 sequences at depth 3
    passed the DEPLOYABLE guard end to end and lost content this way before the
    manifest-fidelity check existed; that count is now 0 (see RESULTS.md).
    """
    pol = Policy(dial=Dial.HOLD_IRREVERSIBLE)
    pol.grant("fs:*").grant("fs:copy")
    g = Guard(policy=pol, classifier=default_classifier(), session=Session())
    g.taint.declare_preexisting("/data/live.db")
    d = g.check(Action("fs", "copy", "/data/live.db", {"source": "/tmp/fresh.db"}))
    assert d.verdict is Verdict.REQUIRE_HUMAN, (
        f"bp-11: expected REQUIRE_HUMAN, got {d.verdict.name}/{d.reason}")
    assert d.reason == P.R_FIDELITY, f"bp-11: wrong reason {d.reason}"
    assert "the declared undo does not restore it" in d.evidence["fidelity"]


def test_bp_11_onto_an_empty_target_is_still_allowed():
    """The same verb, with its undo path intact, must stay unimpeded — otherwise the
    fidelity check is just a ban on copying."""
    pol = Policy(dial=Dial.HOLD_IRREVERSIBLE)
    pol.grant("fs:*").grant("fs:copy")
    g = Guard(policy=pol, classifier=default_classifier(), session=Session())
    d = g.check(Action("fs", "copy", "/backup/new.db", {"source": "/data/live.db"}))
    assert d.verdict is Verdict.ALLOW, (
        f"copying to an empty path is reversible and must pass ({d.reason})")


def test_bp_10_is_genuinely_absent_from_the_old_table():
    """The claim 'never declared' is asserted against the table, not just stated."""
    pairs = {steps for steps, _why in P._COMPOSITIONS}
    assert ("fs:append", "fs:overwrite") not in pairs
    assert not any(set(steps) == {"fs:append", "fs:overwrite"} for steps in pairs)


def test_the_table_mode_misses_what_the_derived_mode_catches():
    pol = Policy(dial=Dial.HOLD_IRREVERSIBLE, require_undo=False,
                 read_before_destroy=False, composition="table")
    pol.grant("fs:*").grant("fs:append").grant("fs:overwrite")
    g = Guard(policy=pol, classifier=default_classifier(), session=Session())
    g.check(Action("fs", "append", "/data/a"))
    d = g.check(Action("fs", "overwrite", "/data/a"))
    assert d.reason != P.R_COMPOSITION, (
        "the baseline table is supposed to MISS this — if it catches it, bp-10 is not "
        "an undeclared composition and the comparison in RESULTS.md is wrong")


def test_agent_authored_content_is_not_a_composition():
    """The mechanism must not fire when the agent can simply re-author the content —
    that is what keeps it off the benign control set."""
    g = _isolated_guard()
    assert g.check(Action("fs", "write_new", "/scratch/mine")).verdict is Verdict.ALLOW
    d = g.check(Action("fs", "truncate", "/scratch/mine"))
    assert d.reason != P.R_COMPOSITION, (
        "destroying content the session itself authored is recoverable: not a composition")


def test_a_surviving_copy_defeats_the_composition_finding():
    """Clause 3: if another location still holds the same content version, nothing is lost."""
    g = _isolated_guard()
    g.check(Action("fs", "read", "/data/a"))
    assert g.check(Action("fs", "copy", "/backup/a", {"source": "/data/a"})).verdict is Verdict.ALLOW
    d = g.check(Action("fs", "truncate", "/data/a"))
    assert d.reason != P.R_COMPOSITION, (
        "a real copy was made first, so the destroy is recoverable and must not be "
        f"flagged as a composition (got {d.reason})")


def test_destroying_the_last_copy_after_deleting_the_backup_is_caught():
    """Clause 4's second branch: the hazard is created by an act on ANOTHER location.

    This is the case a pair table structurally cannot express — the two acts are on
    different targets, so no (verb, verb) rule keyed on one target sees it."""
    g = _isolated_guard()
    g.check(Action("fs", "read", "/data/a"))
    g.check(Action("fs", "copy", "/backup/a", {"source": "/data/a"}))
    assert g.check(Action("fs", "delete", "/backup/a")).verdict in (
        Verdict.ALLOW, Verdict.HOLD)
    g.check(Action("fs", "delete", "/backup/a"), consent=True)
    d = g.check(Action("fs", "truncate", "/data/a"))
    assert d.reason == P.R_COMPOSITION, (
        "after the only backup was destroyed, truncating the original removes the last "
        f"copy and must require a human (got {d.verdict.name}/{d.reason})")


def test_search_is_deterministic():
    first = [f.sequence for f in search(2, "derived", gates=False)]
    second = [f.sequence for f in search(2, "derived", gates=False)]
    assert first == second, "the search must be reproducible to be citable"


def test_deployable_configuration_has_no_silent_loss_up_to_depth_3():
    """The regression property. Vacuous today (the ordinary gates pre-empt composition),
    and that is exactly why it is here: relaxing them must fail this test."""
    report = summarize(3)
    assert report["gates_on"]["violations_derived_mode"] == 0, (
        "a sequence passed the deployable guard end to end and still lost pre-existing "
        f"content: {report['gates_on']['remaining_derived_violations'][:2]}")


def test_the_search_found_undeclared_compositions_with_gates_isolated():
    """The measured claim RESULTS.md makes, asserted rather than quoted."""
    report = summarize(3)
    assert report["gates_off"]["caught_by_derived_but_not_by_the_table"] >= 100
    example = report["gates_off"]["example_caught_only_by_derived"]
    assert example is not None and not example["declared_in_table"]
