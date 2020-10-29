use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::other::{get_network_type, sync_to_tip};
use ckb_index::{with_index_db, IndexDatabase};
use ckb_sdk::{GenesisInfo, HttpRpcClient};
use ckb_types::{
    core::{service::Request, HeaderView},
    prelude::*,
    H256,
};
use ckb_util::RwLock;
use crossbeam_channel::Sender;
use serde_derive::{Deserialize, Serialize};

pub enum IndexRequest {
    Kick,
    RebuildCurrentDB,
    UpdateUrl(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndexResponse {
    Ok,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityResult {
    pub lock_hash: H256,
    pub address: Option<String>,
    pub capacity: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleBlockInfo {
    epoch: (u64, u64, u64),
    number: u64,
    hash: H256,
}

impl From<HeaderView> for SimpleBlockInfo {
    fn from(header: HeaderView) -> SimpleBlockInfo {
        let epoch = header.epoch();
        SimpleBlockInfo {
            number: header.number(),
            epoch: (epoch.number(), epoch.index(), epoch.length()),
            hash: header.hash().unpack(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum IndexThreadState {
    // wait first request to start
    WaitToStart,
    // Started init db
    StartInit,
    // Process after init db
    Processing(Option<SimpleBlockInfo>, u64),
    Error(String),
    // Thread exit
    Stopped,
}

impl IndexThreadState {
    pub fn start_init(&mut self) {
        *self = IndexThreadState::StartInit;
    }
    pub fn processing(&mut self, header: Option<HeaderView>, tip_number: u64) {
        let block_info = header.map(Into::into);
        *self = IndexThreadState::Processing(block_info, tip_number);
    }
    pub fn error(&mut self, err: String) {
        *self = IndexThreadState::Error(err);
    }
    pub fn stop(&mut self) {
        *self = IndexThreadState::Stopped;
    }
    pub fn get_error(&self) -> Option<String> {
        match self {
            IndexThreadState::Error(err) => Some(err.clone()),
            _ => None,
        }
    }
    pub fn is_started(&self) -> bool {
        match self {
            IndexThreadState::WaitToStart => false,
            _ => true,
        }
    }
    pub fn is_stopped(&self) -> bool {
        match self {
            IndexThreadState::Stopped => true,
            _ => false,
        }
    }
    pub fn is_synced(&self) -> bool {
        match self {
            IndexThreadState::Processing(Some(SimpleBlockInfo { number, .. }), tip_number) => {
                number == tip_number
            }
            _ => false,
        }
    }
    pub fn is_error(&self) -> bool {
        match self {
            IndexThreadState::Error(_) => true,
            _ => false,
        }
    }
    #[cfg_attr(windows, allow(dead_code))]
    pub fn is_processing(&self) -> bool {
        match self {
            IndexThreadState::Processing(Some(_), _) => true,
            _ => false,
        }
    }
}

impl fmt::Display for IndexThreadState {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let output = match self {
            IndexThreadState::WaitToStart => "Waiting for first query".to_owned(),
            IndexThreadState::StartInit => "Initializing".to_owned(),
            IndexThreadState::Error(err) => format!("Error: {}", err),
            IndexThreadState::Processing(Some(SimpleBlockInfo { number, .. }), tip_number) => {
                let status = if tip_number == number {
                    "synced".to_owned()
                } else {
                    format!("tip#{}", tip_number)
                };
                format!("Processed block#{} ({})", number, status)
            }
            IndexThreadState::Processing(None, tip_number) => {
                format!("Initializing (tip#{})", tip_number)
            }
            IndexThreadState::Stopped => "Stopped".to_owned(),
        };
        write!(f, "{}", output)
    }
}

impl Default for IndexThreadState {
    fn default() -> IndexThreadState {
        IndexThreadState::WaitToStart
    }
}

pub struct IndexController {
    state: Arc<RwLock<IndexThreadState>>,
    sender: Sender<Request<IndexRequest, IndexResponse>>,
    shutdown: Arc<AtomicBool>,
}

impl Clone for IndexController {
    fn clone(&self) -> IndexController {
        IndexController {
            state: Arc::clone(&self.state),
            shutdown: Arc::clone(&self.shutdown),
            sender: self.sender.clone(),
        }
    }
}

impl IndexController {
    pub fn new(
        state: Arc<RwLock<IndexThreadState>>,
        sender: Sender<Request<IndexRequest, IndexResponse>>,
        shutdown: Arc<AtomicBool>,
    ) -> IndexController {
        IndexController {
            state,
            sender,
            shutdown,
        }
    }
    pub fn state(&self) -> &Arc<RwLock<IndexThreadState>> {
        &self.state
    }
    pub fn sender(&self) -> &Sender<Request<IndexRequest, IndexResponse>> {
        &self.sender
    }
    pub fn shutdown(&self) {
        let start_time = Instant::now();
        self.shutdown.store(true, Ordering::Relaxed);
        while self.state().read().is_started() && !self.state().read().is_stopped() {
            if self.state().read().is_error() {
                return;
            }
            if start_time.elapsed() < Duration::from_secs(10) {
                thread::sleep(Duration::from_millis(50));
            } else {
                eprintln!(
                    "Stop index thread timeout(state: {}), give up",
                    self.state().read().to_string()
                );
                return;
            }
        }
    }
}

pub fn with_db<F, T>(
    func: F,
    rpc_client: &mut HttpRpcClient,
    genesis_info: GenesisInfo,
    index_dir: &PathBuf,
    index_controller: IndexController,
    wait_for_sync: bool,
) -> Result<T, String>
where
    F: FnOnce(IndexDatabase) -> T,
{
    if wait_for_sync {
        sync_to_tip(&index_controller)?;
    }
    let network_type = get_network_type(rpc_client)?;
    let genesis_hash: H256 = genesis_info.header().hash().unpack();
    with_index_db(&index_dir, genesis_hash, |backend, cf| {
        let db = IndexDatabase::from_db(backend, cf, network_type, genesis_info, false)?;
        Ok(func(db))
    })
    .map_err(|_err| {
        format!(
            "Index database may not ready, sync process: {}",
            index_controller.state().read().to_string()
        )
    })
}
