# From evidence to a testable flow

Start at the decision the person is trying to make, not at a list of screens.
For each material source record an ID, provenance, date, and one of:
observed (reproduced/seen), reported (attributed but not reproduced), assumed
(proposed), unknown (a question). A stakeholder estimate is not analytics;
an invented persona is not a research participant. Redact identifying data.

Trace one ordinary completion and the most consequential failure first. Record:
entry and preconditions → action → feedback/result → next action or recovery.
Split actors when permissions or goals differ, not just because devices differ.
Add optional paths only when supported by scope. For an operational interface,
speed is useful only if the person can see what will happen and recover safely.

Example, illustrative only: a finance user reviews invoices and a manager
approves a selection on a phone. J-01 selects specific eligible records;
S-01 shows selection scope and totals, S-02 shows pending submission,
S-03 shows mixed outcomes with failed-record recovery. AC-01 verifies that
changing filters does not silently change which records will be approved.
AC-02 verifies that retry does not replay already completed records. Both need
server-contract evidence before a claim about duplicate side effects is possible.

Separate design questions (where to show scope) from domain questions (who can
approve, financial limits, idempotency). Name decision owners. Do not silently
turn an owner's “one click” aspiration into permission for irreversible bulk
actions. Offer the interaction and state model; leave backend authorization to
the approved spec and security workflow.

Validate with available evidence: task walkthrough, representative content,
prototype usability session if authorized, or reproducible browser exercise.
Define success before testing, e.g. correct record selection and safe recovery;
do not invent a completion-rate improvement or usability score. Label internal
walkthroughs separately from real participant research.

Keep the next handoff small: approved brief + relevant screen/state inventory +
unresolved decisions. Existing journey IDs survive visual redesign; obsolete
states are marked superseded rather than silently reused for another behavior.
