# Component responsibilities

The runtime keeps boundaries explicit: configuration never executes shell strings;
path handling resolves symlinks inside the repository; process execution uses
argument arrays; evidence binds checks to commit and diff identities; documentation
renders only validated model data; and provider adapters cannot weaken canonical
review policy.

Project Memory is not a transcript recorder. It accepts structured, redacted
checkpoints, keeps candidates private, and requires review before shared promotion.
