---
id: ADR-0003
title: Fork-owned image and OCI Helm chart on GHCR
status: accepted
date: 2026-10-01
decision-makers: [repository-owner]
consulted: []
informed: []
supersedes: null
superseded-by: null
---

# Context

The fork's Dockerfile defaults to official PgDog builder/runtime images,
active Compose examples use the official runtime image, and root installation
instructions use an external upstream Helm chart. The package workflow uses
fork-derived package names but requires separate base-image releases and
Blacksmith runners. There is no chart source in this repository.

# Decision drivers

- Own the build and distribution of this fork's application artifacts.
- Keep source, validation and publishing instructions together.
- Avoid a prerequisite base-image release or additional chart-serving website.
- Preserve manual publication, independent review and release gates.

# Considered options

## Self-contained Docker build and GHCR OCI chart

One multi-stage build consumes versioned public OS/Rust bases and repository
source. GHCR stores the resulting image and versioned OCI Helm chart. This
removes official PgDog artifact dependencies and separate base release state.

## Fork-owned builder/runtime packages

Keep the current split and publish both bases in the fork namespace. It can
improve base reuse but adds mutable reference and release synchronization risks.

## Chart repository on GitHub Pages

Supports traditional `helm repo add` but requires chart index maintenance and
a second publication lifecycle alongside architecture documentation.

# Decision

Use `ghcr.io/devfun2026/fork-pgdog` for a self-contained multi-stage image and
`oci://ghcr.io/devfun2026/charts/fork-pgdog` for the chart maintained under
`charts/fork-pgdog`. Use GitHub-hosted packaging runners and manual workflows.
The owner explicitly approved this direction in chat on 2026-10-01 (`duyệt`).
Acceptance applies to this architecture choice; the detailed specification and
implementation plan retain their separate review gates.

# Rationale

The selected approach meets artifact independence with one registry and fewer
release prerequisites. Operators can pin immutable image and chart digests.
Existing Rust Git dependencies and public OS/package registries remain external.

# Consequences

The fork owns versioning, registry access, build caches, chart compatibility,
vulnerability response and publication recovery. A clean image build takes
longer than reusing a prepublished builder. OCI installation uses `oci://`
references instead of the upstream Helm repository. No registry visibility or
production deployment is changed by accepting this decision.

# Risks and mitigations

The proposed [specification](../superpowers/specs/2026-10-01-fork-image-helm-design.md)
records ownership and controls for credentials, source/digest binding, supply
chain, Pod privileges, database outage and runtime-dependent shutdown. Actual
security clearance depends on current implementation evidence and independent
review; this decision does not provide it.

# Follow-up

Approve the detailed spec, then produce and review the implementation plan.
Implement and verify both architectures, isolated Kubernetes behavior,
documentation/model updates and the threat-model delta. Obtain authorization
for first publication and verify pulled GHCR artifacts before claiming external
distribution complete.

# Evidence

- Owner request and design approval in the current conversation.
- [Detailed specification and source evidence](../superpowers/specs/2026-10-01-fork-image-helm-design.md).
- [Current model](../../.agent/project-model/components.toml) and
  [current threat model](../security/threat-model.md); implementation will
  extend these documents before completion.
- Verification evidence is pending implementation; no build or publication
  success is implied by this accepted architecture decision.
