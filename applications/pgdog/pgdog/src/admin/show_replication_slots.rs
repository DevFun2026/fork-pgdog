use std::time::SystemTime;

use chrono::{DateTime, Local};

use crate::{
    backend::replication::logical::publisher::replication_slot::ReplicationSlots,
    net::{ToDataRowColumn, data_row::Data},
    util::{format_bytes, format_time},
};

use super::prelude::*;

pub(crate) struct ShowReplicationSlots;

fn last_transaction_age_ms(last_transaction: Option<SystemTime>, now: SystemTime) -> Option<i64> {
    last_transaction
        .map(|transaction| now.duration_since(transaction).unwrap_or_default())
        .map(|duration| duration.as_millis() as i64)
}

#[async_trait]
impl Command for ShowReplicationSlots {
    fn name(&self) -> String {
        "SHOW REPLICATION_SLOTS".into()
    }

    fn parse(_sql: &str) -> Result<Self, Error> {
        Ok(ShowReplicationSlots {})
    }

    async fn execute(&self) -> Result<Vec<Message>, Error> {
        let rd = RowDescription::new(&[
            Field::text("host"),
            Field::bigint("port"),
            Field::text("database_name"),
            Field::text("name"),
            Field::text("lsn"),
            Field::text("lag"),
            Field::bigint("lag_bytes"),
            Field::bool("temporary"),
            Field::bool("existing"),
            Field::text("last_transaction"),
            Field::bigint("last_transaction_ms"),
            Field::bigint("task_id"),
        ]);
        let mut messages = vec![rd.message()];
        let slots = ReplicationSlots::snapshot();
        let now = SystemTime::now();

        for slot in slots {
            let last_transaction_ms = last_transaction_age_ms(slot.last_transaction, now);

            let last_transaction_str = slot
                .last_transaction
                .map(|t| format_time(DateTime::<Local>::from(t)));

            let mut row = DataRow::new();
            row.add(&slot.address.host)
                .add(slot.address.port as i64)
                .add(&slot.address.database_name)
                .add(slot.name.as_str())
                .add(slot.lsn.to_string().as_str())
                .add(format_bytes(slot.lag as u64).as_str())
                .add(slot.lag)
                .add(slot.temporary)
                .add(slot.existing)
                .add(if let Some(s) = &last_transaction_str {
                    s.as_str().to_data_row_column()
                } else {
                    Data::null()
                })
                .add(if let Some(ms) = last_transaction_ms {
                    ms.to_data_row_column()
                } else {
                    Data::null()
                })
                .add(if let Some(task_id) = slot.task_id {
                    task_id.to_data_row_column()
                } else {
                    Data::null()
                });

            messages.push(row.message());
        }

        Ok(messages)
    }
}

#[cfg(test)]
mod tests {
    use super::last_transaction_age_ms;
    use std::time::{Duration, SystemTime};

    #[test]
    fn last_transaction_age_preserves_past_and_missing_values() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let past = now - Duration::from_millis(1_500);

        assert_eq!(last_transaction_age_ms(Some(past), now), Some(1_500));
        assert_eq!(last_transaction_age_ms(None, now), None);
    }

    #[test]
    fn future_last_transaction_has_zero_age() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10);
        let future = now + Duration::from_millis(1);

        assert_eq!(last_transaction_age_ms(Some(future), now), Some(0));
    }
}
