use uuid::Uuid;

pub(crate) mod context;
pub(crate) mod context_builder;
pub(crate) mod error;
pub(crate) mod ffi;
pub(crate) mod hasher;
pub(crate) mod lookup;
pub(crate) mod mapping;
pub(crate) mod operator;
pub(crate) mod schema;
pub(crate) mod tables;
#[cfg(test)]
pub(crate) mod test;
pub(crate) mod value;

pub(crate) use context::*;
pub(crate) use context_builder::*;
pub(crate) use error::Error;
pub(crate) use hasher::Hasher;
pub(crate) use lookup::{
    LookupCache, LookupStats, LookupTable, PendingLookup, ResolvedLookups, ShardOrLookup,
};
pub(crate) use mapping::Mapping;
pub(crate) use operator::*;
pub(crate) use pgdog_vector::Centroids;
pub(crate) use schema::SchemaSharder;
pub(crate) use tables::*;
pub(crate) use value::*;

const HASH_PARTITION_SEED: u64 = 0x7A5B22367996DCFD;

/// Hash `BIGINT`.
pub(crate) fn bigint(id: i64) -> u64 {
    // SAFETY: The linked PostgreSQL hash routines take integer values by value and do not dereference caller memory.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { ffi::hash_combine64(0, ffi::hashint8extended(id)) }
}

/// Hash UUID.
pub(crate) fn uuid(uuid: Uuid) -> u64 {
    // SAFETY: The live UUID provides 16 initialized bytes; checked c_int length matches the C ABI.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        ffi::hash_combine64(
            0,
            ffi::hash_bytes_extended(
                uuid.as_bytes().as_ptr(),
                hash_key_len(uuid.as_bytes().len()),
                HASH_PARTITION_SEED,
            ),
        )
    }
}

/// Hash VARCHAR.
pub(crate) fn varchar(s: &[u8]) -> u64 {
    // SAFETY: The borrowed slice remains live during the C call; checked c_int length prevents truncation.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe {
        ffi::hash_combine64(
            0,
            ffi::hash_bytes_extended(s.as_ptr(), hash_key_len(s.len()), HASH_PARTITION_SEED),
        )
    }
}

/// hashtext(`s`) equivalient behavior
pub(crate) fn varchar_not_extended(s: &[u8]) -> u32 {
    // SAFETY: The borrowed slice remains live during the C call; checked c_int length prevents truncation.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { ffi::hash_bytes(s.as_ptr(), hash_key_len(s.len())) }
}

/// hashtextextended(`s`, `seed`) equivalient behavior
pub(crate) fn varchar_extended(s: &[u8], seed: u64) -> u64 {
    // SAFETY: The borrowed slice remains live during the C call; checked c_int length prevents truncation.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage
    unsafe { ffi::hash_bytes_extended(s.as_ptr(), hash_key_len(s.len()), seed) }
}

#[cfg(test)]
pub(crate) use test_impls::shard_value;
#[cfg(test)]
mod test_impls {
    use super::{Centroids, bigint, uuid, varchar};
    use crate::config::DataType;
    use crate::frontend::router::parser::Shard;
    use crate::net::{messages::Vector, vector::str_to_vector};

    /// Shard a value that's coming out of the query text directly.
    pub(crate) fn shard_value(
        value: &str,
        data_type: &DataType,
        shards: usize,
        centroids: &Vec<Vector>,
        centroid_probes: usize,
    ) -> Shard {
        match data_type {
            DataType::Bigint => value
                .parse()
                .map(|v| bigint(v) as usize % shards)
                .ok()
                .map(Shard::Direct)
                .unwrap_or(Shard::All),
            DataType::Uuid => value
                .parse()
                .map(|v| uuid(v) as usize % shards)
                .ok()
                .map(Shard::Direct)
                .unwrap_or(Shard::All),
            DataType::Vector => str_to_vector(value)
                .ok()
                .map(|v| {
                    Centroids::from(centroids)
                        .shard(&v, shards, centroid_probes)
                        .into()
                })
                .unwrap_or(Shard::All),
            DataType::Varchar => Shard::Direct(varchar(value.as_bytes()) as usize % shards),
        }
    }
}

#[cfg(test)]
mod ffi_length_tests {
    #[test]
    fn hash_length_matches_c_int_and_rejects_overflow() {
        assert_eq!(super::hash_key_len(0), 0);
        assert_eq!(super::hash_key_len(i32::MAX as usize), i32::MAX);
        assert!(std::panic::catch_unwind(|| super::hash_key_len(i32::MAX as usize + 1)).is_err());
    }
}

fn hash_key_len(len: usize) -> std::ffi::c_int {
    len.try_into().expect("hash input length exceeds C int")
}
