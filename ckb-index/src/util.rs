use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use numext_fixed_hash::H256;
use rocksdb::{ColumnFamily, Options, DB};

use crate::{Error, ROCKSDB_COL_INDEX_DB};

pub fn with_rocksdb<P, T, F>(path: P, timeout: Option<Duration>, func: F) -> Result<T, Error>
where
    P: AsRef<Path>,
    F: FnOnce(&DB) -> Result<T, Error>,
{
    let path = path.as_ref().to_path_buf();
    let start = Instant::now();
    let timeout = timeout.unwrap_or(Duration::from_secs(3));
    let mut options = Options::default();
    options.create_if_missing(true);
    options.create_missing_column_families(true);
    options.set_keep_log_file_num(32);
    let columns = vec![ROCKSDB_COL_INDEX_DB];
    loop {
        match DB::open_cf(&options, &path, &columns) {
            Ok(db) => break func(&db),
            Err(err) => {
                if start.elapsed() >= timeout {
                    log::warn!(
                        "Open rocksdb failed with error={}, timeout={:?}",
                        err,
                        timeout
                    );
                    break Err(err.into());
                }
                log::debug!("Failed open rocksdb: path={:?}, error={}", path, err);
                thread::sleep(Duration::from_millis(200));
            }
        }
    }
}

pub fn with_index_db<P, T, F>(path: P, genesis_hash: H256, func: F) -> Result<T, Error>
where
    P: AsRef<Path>,
    F: FnOnce(&DB, ColumnFamily) -> Result<T, Error>,
{
    let mut directory = path.as_ref().to_path_buf();
    directory.push(format!("{:#x}", genesis_hash));
    std::fs::create_dir_all(&directory)?;
    with_rocksdb(directory, None, |db| {
        let cf = db.cf_handle(ROCKSDB_COL_INDEX_DB).unwrap_or_else(|| {
            db.create_cf(ROCKSDB_COL_INDEX_DB, &Options::default())
                .unwrap_or_else(|_| panic!("Create ColumnFamily {} failed", ROCKSDB_COL_INDEX_DB))
        });
        func(db, cf)
    })
}
