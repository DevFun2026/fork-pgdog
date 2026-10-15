#!/bin/bash
set -euo pipefail

if [ "$#" -lt 4 ]; then
    echo "usage: count_snapshot.sh SOURCE_DB SHARD0_DB SHARD1_DB TABLE..." >&2
    exit 2
fi

SOURCE_DB=$1
SHARD0_DB=$2
SHARD1_DB=$3
shift 3

count_one() {
    local db=$1 table=$2 count
    if [[ ! "${table}" =~ ^[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*$ ]]; then
        echo "invalid table name in count snapshot" >&2
        return 2
    fi
    if ! count=$(
        psql -X -v ON_ERROR_STOP=1 -d "${db}" -tAc "SELECT COUNT(*) FROM ${table}" |
            tr -d '[:space:]'
    ); then
        return 1
    fi
    if [[ ! "${count}" =~ ^[0-9]+$ ]]; then
        echo "count query returned an invalid result for ${table} on ${db}" >&2
        return 1
    fi
    printf '%s' "${count}"
}

for table in "$@"; do
    source_count=$(count_one "${SOURCE_DB}" "${table}")
    shard0_count=$(count_one "${SHARD0_DB}" "${table}")
    shard1_count=$(count_one "${SHARD1_DB}" "${table}")
    total=$((shard0_count + shard1_count))
    printf 'DIAG hop=0->2 table=%s source=%s shard0=%s shard1=%s total=%s\n' \
        "${table}" "${source_count}" "${shard0_count}" "${shard1_count}" "${total}"
done
