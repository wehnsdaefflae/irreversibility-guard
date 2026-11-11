"""Effect-taint closure: DERIVING composite irreversibility instead of listing it.

The first version of this guard detected dangerous *compositions* with a table of four
hard-coded verb pairs (`guard/policy.py:_COMPOSITIONS`). That is a blocklist, not a
mechanism: it catches exactly the sequences its author thought of, and an attacker only
has to compose a fifth. This module replaces it, and keeps the table reachable as a
named baseline (`Policy(composition="table")`) so the difference is measured rather
than claimed.

The model has three parts.

* **Content identity.** Every *location* (a path, a record, an endpoint) holds at most
  one content version, identified by an opaque cid. A backup is simply two locations
  holding the SAME cid.
* **Provenance.** A content version is either ``agent`` — this session authored it, so
  the agent can author it again, and destroying it is recoverable — or ``preexisting``:
  it came from the world and nothing in the session can reconstruct it. Unknown
  provenance FAILS CLOSED as ``preexisting``.
* **Effects.** Each verb maps to one effect on that world: ``none``, ``create``,
  ``extend``, ``replace``, ``destroy``, ``emit``. The mapping is declarative and
  per-verb; an undeclared, non-reversible verb fails closed as ``destroy``.

Composite irreversibility is then derived: an act is composite-irreversible when

1. its effect ``replace``s or ``destroy``s the content at its target location, AND
2. that content's provenance is ``preexisting`` (the agent cannot re-author it), AND
3. no OTHER location holds the same cid (there is no surviving copy), AND
4. the session itself removed the recoverability — either it already acted on that
   location, or it destroyed another location that held the same cid.

Clause 4 is what makes this a closure rather than a pair table: the hazard may be
created several steps earlier, by an act on a *different* location, and the derivation
still finds it. Clause 4 is also what keeps the mechanism off a bare destructive act
that the session did not make more dangerous — such an act is irreversible on its own
account and is caught by the ordinary gates (read-before-destroy, undo path, hold and
re-consent) with their own, clearer reason codes.

`guard/search.py` searches action sequences for violations of the resulting property
against an independent concrete world model.

**Known limits** (also in LIMITATIONS.md): the effect map is a declaration, so a verb
whose real effect differs from its declaration is misjudged exactly as the manifest is;
provenance is session-local, so content written by an EARLIER session reads as
``preexisting`` (fail-closed, which can over-block); and "a copy exists" is tracked
structurally from copy-style acts, not verified against storage, so a copy that a
process outside the guard deleted still counts.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .classifier import REVERSIBLE, ManifestEntry

# ---------------------------------------------------------------- effects
NONE = "none"
CREATE = "create"
EXTEND = "extend"
REPLACE = "replace"
DESTROY = "destroy"
EMIT = "emit"
EFFECTS = (NONE, CREATE, EXTEND, REPLACE, DESTROY, EMIT)

# Declarative per-verb effect map, keyed on the BARE verb of the RESOLVED (de-aliased)
# qualified verb. Extending this table is how a new tool surface is described; it is
# not where compositions are listed.
EFFECT_BY_VERB: dict[str, str] = {
    # observations change nothing
    "read": NONE, "list": NONE, "get": NONE, "stat": NONE, "show": NONE, "head": NONE,
    "cat": NONE, "view": NONE, "search": NONE, "grep": NONE, "find": NONE, "diff": NONE,
    "status": NONE, "describe": NONE, "dry_run": NONE, "preview": NONE, "plan": NONE,
    "simulate": NONE, "count": NONE,
    # bring new content into existence (optionally copying an existing version)
    "write_new": CREATE, "create": CREATE, "copy": CREATE, "cp": CREATE, "backup": CREATE,
    "snapshot": CREATE, "draft": CREATE, "commit": CREATE, "clone": CREATE, "checkout": CREATE,
    # keep prior bytes and add to them
    "append": EXTEND, "add": EXTEND,
    # swap the content for different content
    "overwrite": REPLACE, "clobber": REPLACE, "reset_hard": REPLACE, "restore": REPLACE,
    # remove the content
    "truncate": DESTROY, "delete": DESTROY, "destroy": DESTROY, "erase": DESTROY,
    "purge": DESTROY, "drop": DESTROY, "wipe": DESTROY, "rm": DESTROY, "remove": DESTROY,
    "shred": DESTROY, "revoke": DESTROY, "rotate": DESTROY,
    # leave the trust boundary; nothing local changes and nothing can be recalled
    "send": EMIT, "post": EMIT, "publish": EMIT, "submit": EMIT, "deploy": EMIT,
    "release": EMIT, "email": EMIT, "mail": EMIT, "tweet": EMIT, "push": EMIT,
    "pay": EMIT, "spend": EMIT, "charge": EMIT, "transfer": EMIT, "buy": EMIT, "order": EMIT,
}

# argument names that name the content version a create-style act copies FROM
SOURCE_ARGS = ("source", "src", "from", "from_path", "copy_of")


def effect_of(qualified_verb: str, entry: ManifestEntry | None = None) -> str:
    """The declared effect of a verb. Fails closed: unknown and not-reversible => destroy."""
    declared = getattr(entry, "effect", "") if entry is not None else ""
    if declared:
        if declared not in EFFECTS:
            raise ValueError(f"bad effect: {declared!r}")
        return declared
    bare = qualified_verb.split(":", 1)[-1].lower()
    mapped = EFFECT_BY_VERB.get(bare)
    if mapped is not None:
        return mapped
    if entry is not None:
        if entry.outward:
            return EMIT
        if entry.reversibility == REVERSIBLE:
            # declared reversible but with an unmapped name: it changes something, but
            # nothing we can claim it destroys. Treat as an extension of the world.
            return EXTEND if entry.undo else NONE
    return DESTROY  # fail closed


# ---------------------------------------------------------------- the world model
AGENT = "agent"
PREEXISTING = "preexisting"


@dataclass(frozen=True)
class Content:
    """One content version. Equality is by cid: two locations with one cid are copies."""

    cid: str
    provenance: str


@dataclass
class TaintState:
    """What the session has done to the recoverability of content.

    Deliberately NOT a filesystem: it records content identity and provenance only, so
    it works for mailboxes, rows, endpoints and anything else a tool addresses.
    """

    at: dict[str, Content] = field(default_factory=dict)        # location -> content
    locations: dict[str, set[str]] = field(default_factory=dict)  # cid -> locations
    touched: set[str] = field(default_factory=set)              # locations the session changed
    copy_destroyed: set[str] = field(default_factory=set)       # cids whose copy count we cut
    history: list[str] = field(default_factory=list)            # canonical world-changing acts
    _counter: int = 0

    # -- maintenance -----------------------------------------------------
    def declare_preexisting(self, *locations: str) -> "TaintState":
        for loc in locations:
            self.at.setdefault(loc, Content(f"pre:{loc}", PREEXISTING))
            self.locations.setdefault(f"pre:{loc}", set()).add(loc)
        return self

    def _ensure(self, loc: str) -> Content:
        """The content at a location we have not seen written: unknown => preexisting."""
        content = self.at.get(loc)
        if content is None:
            content = Content(f"pre:{loc}", PREEXISTING)
            self.at[loc] = content
            self.locations.setdefault(content.cid, set()).add(loc)
        return content

    def _new_cid(self, loc: str) -> str:
        self._counter += 1
        return f"agent:{self._counter}:{loc}"

    def _detach(self, loc: str) -> None:
        old = self.at.pop(loc, None)
        if old is None:
            return
        locs = self.locations.get(old.cid)
        if locs is not None:
            locs.discard(loc)
        # the session has reduced the number of locations holding this version
        self.copy_destroyed.add(old.cid)

    def _place(self, loc: str, content: Content) -> None:
        self._detach(loc)
        self.at[loc] = content
        self.locations.setdefault(content.cid, set()).add(loc)

    def copies_of(self, loc: str) -> set[str]:
        content = self.at.get(loc)
        if content is None:
            return set()
        return set(self.locations.get(content.cid, set())) - {loc}

    # -- the derivation --------------------------------------------------
    def effective_effect(self, action, effect: str) -> str:
        """The effect an act really has on the world, which is not always its declared one.

        **A create whose target is already occupied is a replace.** `fs:copy` and
        `fs:write_new` are declared reversible with the undo "delete what was created",
        and that undo is only true of an EMPTY target: copying or writing onto a location
        that already holds content destroys that content, and deleting the result does
        not bring it back. The search in guard/search.py found this as 184 sequences at
        depth 3 that passed the deployable guard end to end and still lost pre-existing
        content — a manifest-fidelity hazard, found by the mechanism rather than guessed,
        and the reason this method exists. `extend` is left alone: appending keeps the
        prior bytes by definition.
        """
        loc = getattr(action, "target", "")
        if effect == CREATE and loc and loc in self.at:
            return REPLACE
        return effect

    def composite_risk(self, action, effect: str) -> str:
        """Why this act is composite-irreversible, or "" if it is not.

        See the module docstring for the four clauses; the order here is the order there.
        """
        effect = self.effective_effect(action, effect)
        if effect not in (REPLACE, DESTROY):
            return ""
        loc = getattr(action, "target", "")
        if not loc:
            return ""
        content = self.at.get(loc)
        if content is None:
            # the session knows nothing about this location's content, so it cannot have
            # made it less recoverable. An ordinary irreversible act: not our business.
            return ""
        if content.provenance == AGENT:
            return ""                      # the agent authored it and can author it again
        survivors = self.copies_of(loc)
        if survivors:
            return ""                      # a copy survives this act
        session_made_it_worse = loc in self.touched or content.cid in self.copy_destroyed
        if not session_made_it_worse:
            return ""
        if loc in self.touched:
            why = f"the session already acted on {loc}"
        else:
            why = f"the session destroyed the only other copy of the content at {loc}"
        return (f"{effect} of {loc} removes the last copy of content this session did not "
                f"author, and {why} — individually reversible steps composing to an "
                f"irrecoverable loss (derived, not listed)")

    def fidelity_risk(self, action, effect: str) -> str:
        """Why an act DECLARED reversible is in fact irrecoverable, or "".

        Separate from `composite_risk` on purpose. A composition needs the session to
        have made things worse (clause 4); this needs nothing but the act itself. It
        catches the case where the manifest's undo path is conditional and the condition
        does not hold — the `create`-onto-occupied hazard `effective_effect` describes.
        A guard that trusted the declaration would allow it silently, which is exactly
        what the search observed.
        """
        loc = getattr(action, "target", "")
        if not loc:
            return ""
        if self.effective_effect(action, effect) != REPLACE or effect != CREATE:
            return ""
        content = self.at.get(loc)
        if content is None or content.provenance == AGENT:
            return ""
        if self.copies_of(loc):
            return ""
        return (f"{action.qualified_verb} is declared reversible because what it creates "
                f"can be deleted, but {loc} already holds content this session did not "
                f"author and no copy survives: the declared undo does not restore it "
                f"(manifest-fidelity hazard, derived)")

    # -- recording -------------------------------------------------------
    def record(self, action, effect: str) -> None:
        """Fold an act the guard ALLOWED into the world model."""
        effect = self.effective_effect(action, effect)
        loc = getattr(action, "target", "")
        if effect == NONE or effect == EMIT or not loc:
            return
        args = dict(getattr(action, "args", {}) or {})
        source = next((str(args[k]) for k in SOURCE_ARGS if k in args and args[k]), "")
        if source and effect in (CREATE, REPLACE):
            # a real copy: the target ends up holding the SAME content version as the
            # source, which is what makes a backup count as a surviving copy under
            # clause 3. This runs even when effective_effect rewrote create->replace,
            # because the act still copies — it just also destroyed what was there.
            self._place(loc, self._ensure(source))
        elif effect == CREATE:
            self._place(loc, Content(self._new_cid(loc), AGENT))
        elif effect == EXTEND:
            self._ensure(loc)            # prior bytes are retained: cid and provenance stand
        elif effect == REPLACE:
            self._place(loc, Content(self._new_cid(loc), AGENT))
        elif effect == DESTROY:
            self._detach(loc)
        self.touched.add(loc)
        self.history.append(action.canonical() if hasattr(action, "canonical") else str(action))
