#!/bin/bash
set -e
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

pushd ${SCRIPT_DIR}

npm install

# Generate Prisma client
DATABASE_URL="postgresql://pgdog:pgdog@127.0.0.1:6432/pgdog" npx prisma generate

# The full ORM suite exceeds 60s with coverage on hosted runners.
# Keep Mocha per-test timeouts and a bounded total runtime.
timeout 300 npm test

popd
