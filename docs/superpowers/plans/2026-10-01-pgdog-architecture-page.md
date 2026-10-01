# PgDog architecture page implementation

Approved in chat on 2026-10-01: adapt the supplied Stargate blueprint layout,
use actual PgDog model data, retain offline support, and publish GitHub Pages
manually from main. Keep the pending root README consolidation in this change.

1. Add regression checks for safe readable Markdown, canonical SVG graphs,
   complete navigation and embedded assets; demonstrate the missing behavior.
2. Replace the renderer with a blueprint layout, sidebar, model-driven diagrams
   and component cards. Keep full focused documentation and escape untrusted
   content. Use system fonts; add no dependency or remote assets.
3. Add a PR/manual Pages workflow. PR builds have read permissions; deployment
   requires manual dispatch on main, Pages/OIDC permissions and github-pages
   environment. Stage only the generated HTML as index.html.
4. Rebuild/check generated docs; run related runtime tests and required gates,
   scanners, responsive and keyboard/browser checks. Prepare an immutable
   Gemini review package through native AGY and obtain its exact-hash approval.
5. After review/adjudication and green merge gate, merge, enable Actions-based
   Pages, deploy manually, verify the public URL, and set repository homepage.

Rollback: retain the previous Pages deployment while a reviewed revert is
prepared and merged to main, then dispatch the manual workflow from main.
The workflow rejects publication from other refs. No PostgreSQL deployment changes.
