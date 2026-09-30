# Security policy

Security work is evidence-bounded. Report the reviewed scope, checks performed,
findings, unverified areas, and residual risks. Never claim that a system is
absolutely secure or certified by an OWASP project.

The approved profile is `baseline`, `standard`, or `high`. An agent may propose
raising it, but may not lower it. Changes to assets, actors, trust boundaries,
external integrations, sensitive data, or data flows require a threat-model
delta. Required scanners may not be reported as passed when missing, skipped,
timed out, or not configured.

Review authentication and authorization; inputs and injection; secrets and
data; sessions and cryptography; business logic and races; supply chain;
infrastructure; and recovery and auditing. AI review complements rather than
replaces deterministic checks.
