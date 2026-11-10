"""Tiered reversibility classification.

Three tiers, consulted in order:

1. **manifest** — a declarative per-tool/per-verb table. Authoritative, and the only
   tier that is *sound*: a human wrote down what the verb does.
2. **heuristic** — pattern matching over the resolved verb and target. Unsound by
   construction; it exists to catch verbs nobody declared.
3. **unknown** — nothing matched. FAILS CLOSED: an undeclared verb is treated as
   irreversible, never as safe.

Aliasing is resolved *before* classification, so a tool renamed or wrapped around
`delete` is classified as `delete`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .core import Action

REVERSIBLE = "reversible"
IRREVERSIBLE = "irreversible"
UNKNOWN = "unknown"

# Verb families whose names alone imply an outward or destroying act.
_IRREVERSIBLE_PATTERNS = (
    r"^(delete|destroy|erase|purge|drop|wipe|rm|remove|truncate|shred)",
    r"^(send|post|publish|submit|deploy|release|email|mail|tweet|push)",
    r"^(pay|spend|charge|transfer|buy|order|refund)",
    r"^(overwrite|clobber|force[_-]?push|reset[_-]?hard|revoke|rotate)",
    r"^(grant|chmod|chown|disable|shutdown|terminate|kill)",
)
_REVERSIBLE_PATTERNS = (
    r"^(read|get|list|show|stat|head|cat|view|search|grep|find|describe|diff|dry[_-]?run)",
    r"^(draft|preview|plan|simulate|count|checkout|clone|fetch)",
)


@dataclass
class ManifestEntry:
    reversibility: str
    undo: str = ""            # how the act is undone; "" = no undo path
    outward: bool = False     # leaves the trust boundary (mail, publish, spend)
    self_modifying: bool = False  # touches the guard's own policy/config/code

    def __post_init__(self) -> None:
        if self.reversibility not in (REVERSIBLE, IRREVERSIBLE, UNKNOWN):
            raise ValueError(f"bad reversibility: {self.reversibility!r}")


@dataclass
class Classification:
    reversibility: str
    tier: str
    entry: ManifestEntry | None = None
    resolved_verb: str = ""
    matched: str = ""

    @property
    def irreversible(self) -> bool:
        # unknown fails closed: treated as irreversible
        return self.reversibility != REVERSIBLE


@dataclass
class Classifier:
    """Manifest-first, heuristics second, fail closed third."""

    manifest: dict[str, ManifestEntry] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)

    def declare(self, qualified_verb: str, entry: ManifestEntry) -> "Classifier":
        self.manifest[qualified_verb] = entry
        return self

    def alias(self, alias_verb: str, real_verb: str) -> "Classifier":
        """`alias_verb` (tool:verb) is a rename/wrapper around `real_verb`."""
        self.aliases[alias_verb] = real_verb
        return self

    def resolve(self, qualified_verb: str) -> str:
        """Follow aliases to a fixpoint (cycle-safe)."""
        seen = {qualified_verb}
        current = qualified_verb
        while current in self.aliases:
            current = self.aliases[current]
            if current in seen:
                break
            seen.add(current)
        return current

    def classify(self, action: Action) -> Classification:
        resolved = self.resolve(action.qualified_verb)
        entry = self.manifest.get(resolved)
        if entry is None:
            # an undeclared tool may still name a declared bare verb
            bare = resolved.split(":", 1)[-1]
            for key, candidate in self.manifest.items():
                if key.split(":", 1)[-1] == bare:
                    entry, resolved = candidate, key
                    break
        if entry is not None:
            return Classification(entry.reversibility, "manifest", entry, resolved, resolved)

        bare = resolved.split(":", 1)[-1].lower()
        for pattern in _IRREVERSIBLE_PATTERNS:
            if re.search(pattern, bare):
                return Classification(
                    IRREVERSIBLE, "heuristic",
                    ManifestEntry(IRREVERSIBLE, outward=bool(re.search(_IRREVERSIBLE_PATTERNS[1], bare))),
                    resolved, pattern,
                )
        for pattern in _REVERSIBLE_PATTERNS:
            if re.search(pattern, bare):
                return Classification(REVERSIBLE, "heuristic", ManifestEntry(REVERSIBLE), resolved, pattern)

        return Classification(UNKNOWN, "unknown", None, resolved, "")


def default_classifier() -> Classifier:
    """A small worked manifest, mirroring this scheduler instance's own tool surface."""
    c = Classifier()
    m = c.declare
    m("fs:read", ManifestEntry(REVERSIBLE))
    m("fs:list", ManifestEntry(REVERSIBLE))
    m("fs:write_new", ManifestEntry(REVERSIBLE, undo="delete the created file"))
    m("fs:append", ManifestEntry(REVERSIBLE, undo="truncate to the recorded length"))
    m("fs:overwrite", ManifestEntry(IRREVERSIBLE))
    m("fs:truncate", ManifestEntry(IRREVERSIBLE))
    m("fs:delete", ManifestEntry(IRREVERSIBLE))
    m("mail:list", ManifestEntry(REVERSIBLE))
    m("mail:read", ManifestEntry(REVERSIBLE))
    m("mail:draft", ManifestEntry(REVERSIBLE, undo="delete the draft"))
    m("mail:send", ManifestEntry(IRREVERSIBLE, outward=True))
    m("git:status", ManifestEntry(REVERSIBLE))
    m("git:commit", ManifestEntry(REVERSIBLE, undo="git reset --soft HEAD~1"))
    m("git:push", ManifestEntry(IRREVERSIBLE, outward=True))
    m("form:submit", ManifestEntry(IRREVERSIBLE, outward=True))
    m("guard:set_policy", ManifestEntry(IRREVERSIBLE, self_modifying=True))
    m("guard:disable", ManifestEntry(IRREVERSIBLE, self_modifying=True))
    return c
