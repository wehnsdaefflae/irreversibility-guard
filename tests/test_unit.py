"""Unit-level suite: canonicalization, the three classifier tiers, the structural gates."""
from __future__ import annotations

import json

import pytest

from guard import (
    IRREVERSIBLE,
    REVERSIBLE,
    UNKNOWN,
    Action,
    Classifier,
    Dial,
    Guard,
    ManifestEntry,
    Policy,
    Session,
    Verdict,
    default_classifier,
)
from guard import policy as P


# ---------------------------------------------------------------- canonical form
def test_canonical_is_independent_of_kwarg_order():
    a = Action("fs", "delete", "/tmp/x", {"recursive": True, "force": False})
    b = Action("fs", "delete", "/tmp/x", {"force": False, "recursive": True})
    assert a.canonical() == b.canonical() == "fs:delete /tmp/x force=false recursive=true"


def test_canonical_excludes_underscore_args_and_renders_nested():
    a = Action("api", "post", "/v1", {"body": {"b": 1, "a": [2, 3]}, "_trace": "noise"})
    assert a.canonical() == "api:post /v1 body={a=[2,3],b=1}"


def test_canonical_of_batch_contains_every_member():
    batch = Action("fs", "batch", members=[
        Action("fs", "read", "/a"), Action("fs", "delete", "/b"),
    ])
    assert batch.canonical() == "batch[fs:read /a ; fs:delete /b]"


# ---------------------------------------------------------------- classifier tiers
def test_manifest_tier_is_authoritative_over_the_heuristic():
    # "send_report" would match the outward heuristic; the manifest says reversible.
    c = Classifier().declare("report:send_report", ManifestEntry(REVERSIBLE))
    cls = c.classify(Action("report", "send_report"))
    assert (cls.tier, cls.reversibility) == ("manifest", REVERSIBLE)


def test_heuristic_tier_catches_an_undeclared_destroying_verb():
    cls = Classifier().classify(Action("blobstore", "purge_bucket", "b"))
    assert (cls.tier, cls.reversibility) == ("heuristic", IRREVERSIBLE)


def test_unknown_verb_fails_closed():
    cls = Classifier().classify(Action("widget", "frobnicate", "w"))
    assert cls.tier == "unknown"
    assert cls.reversibility == UNKNOWN
    assert cls.irreversible is True, "an unknown verb must be treated as irreversible"


def test_alias_is_resolved_before_classification():
    c = default_classifier().alias("helper:cleanup", "fs:delete")
    cls = c.classify(Action("helper", "cleanup", "/tmp/x"))
    assert cls.resolved_verb == "fs:delete"
    assert cls.reversibility == IRREVERSIBLE


def test_alias_cycle_terminates():
    c = Classifier().alias("a:x", "b:y").alias("b:y", "a:x")
    assert c.resolve("a:x") in {"a:x", "b:y"}


def test_bare_verb_match_catches_a_wrapper_tool():
    # an undeclared TOOL reaching a declared bare verb is still classified
    cls = default_classifier().classify(Action("mytools", "send", "x@example.com"))
    assert cls.tier == "manifest"
    assert cls.reversibility == IRREVERSIBLE


# ---------------------------------------------------------------- capabilities
def _guard(dial=Dial.HOLD_IRREVERSIBLE, **grants):
    pol = Policy(dial=dial)
    for verb in grants.get("verbs", ()):
        pol.grant(verb)
    return Guard(policy=pol, classifier=default_classifier(), session=Session())


def test_wildcard_grant_does_not_cover_the_irreversible_verb():
    g = _guard(verbs=["mail:*"])
    assert g.check(Action("mail", "list")).verdict is Verdict.ALLOW
    d = g.check(Action("mail", "send", "x@example.com"))
    assert d.verdict is Verdict.DENY
    assert d.reason == P.R_NO_CAPABILITY, "mail:* must not grant mail:send"


def test_explicit_verb_grant_is_required_and_sufficient():
    g = _guard(verbs=["mail:*", "mail:send"])
    g.session.grant_go("mail:send x@example.com")
    d = g.check(Action("mail", "send", "x@example.com"))
    assert d.verdict is Verdict.ALLOW and d.reason == P.R_ALLOW_GO


def test_ungranted_verb_is_denied_before_anything_else():
    g = _guard(verbs=[])
    assert g.check(Action("fs", "read", "/a")).reason == P.R_NO_CAPABILITY


# ---------------------------------------------------------------- structural gates
def test_read_before_destroy_refuses_then_permits():
    g = _guard(verbs=["fs:*", "fs:delete"])
    d = g.check(Action("fs", "delete", "/data/report.csv"))
    assert d.verdict is Verdict.DENY and d.reason == P.R_NEEDS_READ
    g.check(Action("fs", "read", "/data/report.csv"))          # now it has been read
    d2 = g.check(Action("fs", "delete", "/data/report.csv"))
    assert d2.verdict is not Verdict.DENY, "after reading, the act is holdable not refused"
    assert d2.reason in (P.R_HOLD_IRREVERSIBLE, P.R_NO_UNDO, P.R_NEEDS_HUMAN)


def test_hold_then_reconsent_allows_the_exact_act_only():
    pol = Policy(dial=Dial.HOLD_IRREVERSIBLE, require_undo=False, read_before_destroy=False)
    pol.grant("fs:truncate")
    g = Guard(policy=pol, classifier=default_classifier(), session=Session())
    first = g.check(Action("fs", "truncate", "/tmp/a"))
    assert first.verdict is Verdict.HOLD and first.reason == P.R_HOLD_IRREVERSIBLE
    again = g.check(Action("fs", "truncate", "/tmp/a"), consent=True)
    assert again.verdict is Verdict.ALLOW and again.reason == P.R_ALLOW_CONSENTED
    # a DIFFERENT act is not covered by that consent
    other = g.check(Action("fs", "truncate", "/tmp/b"), consent=True)
    assert other.verdict is Verdict.HOLD


def test_outward_act_requires_a_go_on_that_exact_canonical_act():
    g = _guard(verbs=["form:submit"])
    d = g.check(Action("form", "submit", "https://drawerrr.com/submit", {"link": "repo-a"}))
    assert d.verdict is Verdict.REQUIRE_HUMAN and d.reason == P.R_NEEDS_HUMAN
    g.session.grant_go("form:submit https://drawerrr.com/submit link=repo-a")
    # the go does NOT cover a changed payload
    changed = g.check(Action("form", "submit", "https://drawerrr.com/submit", {"link": "repo-b"}))
    assert changed.verdict is Verdict.REQUIRE_HUMAN
    exact = g.check(Action("form", "submit", "https://drawerrr.com/submit", {"link": "repo-a"}))
    assert exact.verdict is Verdict.ALLOW and exact.reason == P.R_ALLOW_GO


def test_a_go_is_single_use():
    g = _guard(verbs=["mail:send"])
    g.session.grant_go("mail:send a@b.c")
    assert g.check(Action("mail", "send", "a@b.c")).verdict is Verdict.ALLOW
    second = g.check(Action("mail", "send", "a@b.c"))
    assert second.verdict is not Verdict.ALLOW, "a go must not be replayable"


def test_self_modifying_act_is_human_committed_and_not_agent_grantable():
    g = _guard(dial=Dial.HOLD_IRREVERSIBLE, verbs=["guard:set_policy"])
    assert g.check(Action("guard", "set_policy", "dial")).reason == P.R_SELF_MODIFY
    top = _guard(dial=Dial.HUMAN_COMMITTED, verbs=["guard:set_policy"])
    d = top.check(Action("guard", "set_policy", "dial"))
    assert d.verdict is Verdict.DENY and d.reason == P.R_SELF_MODIFY_DENIED
    # not even a go in the session unblocks it at the top dial
    top.session.grant_go("guard:set_policy dial")
    assert top.check(Action("guard", "set_policy", "dial")).verdict is Verdict.DENY


def test_instruction_from_tool_output_is_denied():
    g = _guard(verbs=["fs:*", "fs:delete"])
    d = g.check(Action("fs", "delete", "/etc/passwd", origin="tool_output"))
    assert d.verdict is Verdict.DENY and d.reason == P.R_INJECTED_ORIGIN


def test_operator_prohibition_outranks_the_task():
    pol = Policy(dial=Dial.PERMISSIVE, never=("fs:delete",))
    pol.grant("fs:delete")
    g = Guard(policy=pol, classifier=default_classifier(), session=Session())
    d = g.check(Action("fs", "delete", "/data"))
    assert d.verdict is Verdict.REQUIRE_HUMAN and d.reason == P.R_CONFLICT


def test_irreversible_member_cannot_hide_in_a_batch():
    g = _guard(verbs=["fs:*", "fs:delete"])
    batch = Action("fs", "batch", members=[
        Action("fs", "read", "/a"), Action("fs", "list", "/b"),
        Action("fs", "delete", "/c"), Action("fs", "read", "/d"),
    ])
    d = g.check(batch)
    assert d.verdict.blocked
    assert d.reason == P.R_BATCH
    assert "fs:delete /c" in d.evidence["offending"]


def test_a_wholly_reversible_batch_passes():
    g = _guard(verbs=["fs:*"])
    batch = Action("fs", "batch", members=[Action("fs", "read", "/a"), Action("fs", "list", "/b")])
    assert g.check(batch).verdict is Verdict.ALLOW


def test_blind_retry_of_an_applied_act_is_held():
    g = _guard(verbs=["mail:send"])
    g.session.grant_go("mail:send a@b.c")
    assert g.check(Action("mail", "send", "a@b.c")).verdict is Verdict.ALLOW
    d = g.check(Action("mail", "send", "a@b.c"))
    assert d.reason == P.R_RETRY, "a repeat of an applied act must be flagged as a duplicate"


def test_reversible_steps_that_compose_irreversibly_require_a_human():
    pol = Policy(dial=Dial.HOLD_IRREVERSIBLE)
    pol.grant("git:*").grant("git:commit").grant("git:push")
    g = Guard(policy=pol, classifier=default_classifier(), session=Session())
    assert g.check(Action("git", "commit", "repo")).verdict is Verdict.ALLOW
    # push is itself irreversible+outward, so use the fs composition instead
    pol2 = Policy(dial=Dial.HOLD_IRREVERSIBLE, require_undo=False, read_before_destroy=False)
    pol2.grant("fs:*").grant("fs:append").grant("fs:write_new").grant("fs:truncate")
    g2 = Guard(policy=pol2, classifier=default_classifier(), session=Session())
    assert g2.check(Action("fs", "append", "/tmp/log")).verdict is Verdict.ALLOW
    d = g2.check(Action("fs", "truncate", "/tmp/log"))
    assert d.verdict is Verdict.REQUIRE_HUMAN or d.reason == P.R_COMPOSITION


# ---------------------------------------------------------------- audit record
def test_audit_log_is_appended_as_jsonl_and_reads_back(tmp_path):
    log = tmp_path / "audit.jsonl"
    pol = Policy(); pol.grant("fs:*")
    g = Guard(policy=pol, classifier=default_classifier(), session=Session(), audit_path=log)
    g.check(Action("fs", "read", "/a"))
    g.check(Action("fs", "delete", "/a"))
    rows = [json.loads(line) for line in log.read_text().splitlines()]
    assert len(rows) == 2
    assert {r["verdict"] for r in rows} == {"ALLOW", "DENY"}
    assert all("reason" in r and "tier" in r and "canonical" in r for r in rows)


def test_feedback_tally_counts_every_verdict():
    g = _guard(verbs=["fs:*"])
    g.check(Action("fs", "read", "/a"))
    g.check(Action("fs", "delete", "/a"))
    assert g.session.tally["ALLOW"] == 1
    assert sum(g.session.tally.values()) == 2


def test_decision_record_round_trips_to_json():
    g = _guard(verbs=["fs:*"])
    d = g.check(Action("fs", "read", "/a"))
    assert json.loads(d.to_json())["reason"] == P.R_ALLOW


@pytest.mark.parametrize("dial", list(Dial))
def test_every_dial_still_refuses_an_ungranted_verb(dial):
    g = _guard(dial=dial, verbs=[])
    assert g.check(Action("fs", "delete", "/a")).verdict is Verdict.DENY
