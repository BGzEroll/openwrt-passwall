# AGENTS.md

## Multi-agent policy

Use the primary Sol model as the orchestrator, technical lead, and final owner of the task.

Prefer delegation only when a task can be cleanly separated and has a clear completion condition.

These model-routing rules may be overridden by explicit user instructions for a specific session or task.

### Model roles

Use **Sol** for:

* architecture decisions
* cross-module implementation
* complex debugging
* concurrency and realtime correctness
* ambiguous requirements
* high-impact changes
* regression fixing
* reviewing important changes
* final integration and task closure

Use **Luna max** preferably for:

* repository exploration
* locating references and call sites
* dependency and control-flow analysis
* codebase summarization
* mechanical refactors
* repetitive edits
* straightforward, well-specified implementation
* documentation updates
* test generation
* build/test execution
* compiler and warning investigation
* collecting evidence for bugs

### Delegation rules

For non-trivial tasks:

1. Analyze the task first.
2. Delegate only work that is narrow, bounded, and independently understandable.
3. Prefer Luna max for investigation, validation, and high-volume mechanical work.
4. Keep Sol responsible for architecture, cross-module reasoning, and final correctness.
5. Do not delegate broad or ambiguous implementation tasks to Luna.
6. Review all Luna findings and code changes before accepting them.
7. Avoid spawning Sol subagents unless an independent high-level review is genuinely useful.
8. Close completed subagent threads when they are no longer needed.

Do not delegate trivial tasks where orchestration overhead exceeds the benefit.

### Implementation policy

Prefer this pattern:

* Luna investigates.
* Sol decides.
* Luna may implement clearly bounded changes.
* Sol integrates and reviews.
* Luna may run build/tests and collect failures.
* Sol owns difficult fixes and final closure.

For changes involving multiple tightly coupled modules, prefer Sol to keep implementation ownership rather than repeatedly handing the work between agents.

### Escalation policy

Do not repeatedly delegate the same failing problem.

If Luna:

* fails to complete the task,
* introduces regressions,
* produces conflicting results,
* becomes uncertain,
* or requires repeated correction,

escalate the task back to Sol.

As a default, after **1–2 unsuccessful Luna iterations**, stop delegating that problem and let Sol take ownership.

Prefer Sol to perform final regression fixing and task closure.

### Primary-agent behavior

The primary Sol agent should behave like the owner of the engineering task rather than merely a coordinator.

Its main responsibilities are:

* understand the request
* determine constraints and invariants
* maintain the overall mental model
* design the approach
* define interfaces and boundaries
* decide what is safe to delegate
* review findings and diffs
* identify architectural and correctness problems
* resolve cross-module issues
* fix regressions
* perform final integration
* determine when the task is actually complete

### Conservative delegation principle

When uncertain whether a task should be delegated, prefer keeping it with Sol.

In particular, keep the task with Sol when it involves:

* architecture
* ownership or lifetime
* concurrency
* realtime behavior
* hardware interactions
* complex networking behavior
* cross-module state
* subtle C/C++ correctness
* repeated regression fixing
* unclear requirements

Use Luna primarily as a focused worker for bounded tasks rather than as an autonomous project owner.

In short:

**Sol = owner / architect / implementer for difficult work / reviewer / closer**

**Luna max = exploration / evidence gathering / mechanical implementation / validation worker**
