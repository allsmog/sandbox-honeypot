# Active work

This file is the durable resumption queue for user-directed and discovered work. Before
implementation, follow `skills/agent/record-user-directed-work/SKILL.md`.
Keep detailed designs in focused roadmap documents and link them here.
Record release scope in the [release-goal manifest](release-goals.json); the release
gate cross-checks it against this queue.

## Detailed-roadmap lifecycle

This file is the sole resumable queue. Create a supporting file beneath `docs/roadmap/`
only when one item cannot keep a program's rationale, ordering, and acceptance contract
readable. Put this visible header immediately after the detailed document's title:

```markdown
- **Status:** active
- **Owning queue item:** [AREA-NNN](active-work.md#area-nnn-heading)
- **Completion / archival evidence:** pending while AREA-NNN remains open
```

Status is exactly `active`, `partial`, `deferred`, `completed`, or `historical`. The
owner must resolve to a checkbox or named program heading in this file. A terminal state
requires linked evidence. Keep a completed plan here only when doing so preserves useful
inbound links; move substantial closed programs beneath `docs/history/roadmap/`, retain
their owner, and mark them `historical`. Do not create a separate file for an ordinary
queue item or let `docs/roadmap/` become a plan archive.

## P0

Check the parent only after every required subtask and evidence item passes. Add the
release-visible outcome to `CHANGELOG.md`; Git preserves prior queue states.

### [ ] TRIP-001 — Host-decoy escape tripwire decision engine

- **Priority:** P0
- **Owner:** components/sandbox-tripwire
- **Direction:** Add a defense-in-depth honeypot that integrates with existing sandboxes (gVisor, Capsem, Firecracker, Kata): host decoys outside the sandbox boundary act as a monitoring tripwire if a workload breaks out. Host decoys only; no in-sandbox canaries.
- **Conclusion:** Version 0.1.0 is a pure, deterministic plan/evaluate engine specified in components/sandbox-tripwire/component.md. It never writes decoys, opens listeners, or runs sensors; materialization and host sensors are a later Component.
- **Depends on:** none
- **Completion prerequisites:** none
- **Implementation:**
  - [ ] Generate, build, and test the Python/Make application with litai rebuild after execution authorization.
- **Evidence:**
  - [ ] litai verify, lock, and plan pass for components/sandbox-tripwire.
  - [ ] Generated tests and independent acceptance pass every specification scenario.
