# Deployment and operation

## Current local setup

Build the Rust workspace from the repository root:

    ./scripts/pgdog cargo build --locked --workspace

Run the upstream Docker demo:

    docker compose -f applications/pgdog/docker-compose.yml up

Build this fork's container using the repository root as its build context:

    docker build -f applications/pgdog/Dockerfile -t pgdog .

Configuration and client connection examples are in README.md. The Docker demo
contains synthetic credentials and data for local evaluation.

## Production work still to be designed

The intended deployment is an EKS-hosted proxy reached through a load balancer
restricted to company IPs, with PostgreSQL in a private subnet and Vault dynamic
credentials. This repository setup has not provisioned that infrastructure or
established production query-audit coverage. Upstream Helm and Terraform links
in README.md describe upstream deployment options.

The LLM agent is planned; this overview does not declare an LLM runtime, model
provider, database access policy or production deployment for it.

## Repository tooling and documentation

scripts/agent runs from the checkout on macOS, Linux or WSL. Hosted CI uses the
same local gates. Validation runs for pull requests or manual dispatch, and
publishing is manual.

The architecture page is generated from .agent/project-model/ and focused docs:

    ./scripts/agent docs build
    ./scripts/agent docs check

system.html is a self-contained file with local styles, search and navigation.
It works offline without a CDN, external JavaScript, database connection or LLM
provider. The embedded security documents cover repository tooling and must be
extended before using them as a production PgDog/LLM security assessment.

## Architecture Pages publication

The Architecture Pages workflow builds a static document from this model.
Pull requests validate it with read-only repository permissions. Only a manual
workflow_dispatch on main can run the deployment job, which has Pages and OIDC
permissions and uses the github-pages environment. The uploaded directory
contains only generated index.html and .nojekyll; no source, credentials,
private memory or local review evidence is exported.

The public URL is intended to be https://devfun2026.github.io/fork-pgdog/.
Repository Pages settings and the first deployment are external setup steps.
Publishing this document does not deploy the PostgreSQL proxy or LLM agent.
