# System context

Project AI Template lives inside a product repository and provides one canonical
workflow to human maintainers and Claude, Gemini via Antigravity CLI (`agy`), or Codex coding agents. Product
source remains outside the template runtime and is read only when an approved
workflow requires it.

External boundaries are installed provider CLI processes and hosted CI runners.
Provider calls receive only an explicitly previewed review package. CI jobs invoke
repository-owned commands and must not expose provider credentials to untrusted code.
