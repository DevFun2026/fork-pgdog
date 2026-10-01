# System context

## Source and purpose

This repository forks PgDog from https://github.com/pgdogdev/pgdog. The PostgreSQL
proxy and its existing features belong to upstream PgDog and its contributors.
The fork's product goal is to add an LLM agent layer on top of that proxy.
The upstream source is under applications/pgdog/; README.md is the main usage
guide. Import history and license attribution are recorded in
docs/import/PGDOG_IMPORT.md and THIRD_PARTY_NOTICES.md.

## Current runtime

PostgreSQL client -> PgDog proxy -> PostgreSQL primary / replicas / shards

Clients use the PostgreSQL wire protocol. PgDog authenticates connections,
maintains backend connection pools, parses and routes queries, and returns
PostgreSQL results. The source includes backend authentication integrations
such as Vault dynamic credentials; production Vault policies and EKS resources
have not been configured by this repository work.

The repository also contains a Python coding-agent runtime for verification,
independent review, documentation and local development memory. This tooling
runs during development and CI; it is not on the PostgreSQL query path.

## Planned LLM agent

The LLM agent is not implemented or deployed. Its interfaces, query access,
provider choice, authorization and handling of database data still require a
separate approved design. No SQL, credentials or query results are currently
sent to an LLM by a runtime agent in this fork.

The intended EKS proxy deployment, company-IP-restricted load balancer and
member query auditing are future deployment/product work. The current diagrams
and component model describe implemented code and repository tooling, not a
claim that this production architecture is running.
