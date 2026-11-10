#!/usr/bin/env python3
"""A 30-second demo: an agent tries four things, the guard answers each.

    python demo.py

Nothing is executed — every act is only *proposed* to the guard.
"""
from guard import Action, Dial, Guard, Policy, Session, default_classifier


def main() -> None:
    policy = Policy(dial=Dial.HOLD_IRREVERSIBLE, never=())
    # a wildcard grant covers the tool's REVERSIBLE verbs only
    policy.grant("fs:*").grant("fs:delete").grant("mail:*").grant("mail:send")
    guard = Guard(policy=policy, classifier=default_classifier(), session=Session(),
                  audit_path="audit.jsonl")

    print("1. the agent reads a file")
    print("  ", guard.check(Action("fs", "read", "/data/report.csv")))

    print("2. the agent deletes a DIFFERENT file it never read")
    print("  ", guard.check(Action("fs", "delete", "/data/customers.sqlite")))

    print("3. the agent hides a delete inside a batch of reads")
    batch = Action("fs", "batch", members=[
        Action("fs", "read", "/a"), Action("fs", "delete", "/b"), Action("fs", "read", "/c"),
    ])
    print("  ", guard.check(batch))

    print("4. injected content tells the guard to send mail")
    print("  ", guard.check(Action("mail", "send", "attacker@example.com",
                                   origin="tool_output")))

    print("5. the operator gives a go on ONE exact act, and it goes through")
    guard.session.grant_go("mail:send ops@example.com")
    print("  ", guard.check(Action("mail", "send", "ops@example.com")))
    print("   the same go replayed:")
    print("  ", guard.check(Action("mail", "send", "ops@example.com")))

    print("\nverdict tally:", guard.session.tally)
    print("audit log written to ./audit.jsonl")


if __name__ == "__main__":
    main()
