use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ckb_index::{with_index_db, IndexDatabase};
use ckb_jsonrpc_types::BlockNumber;
use ckb_sdk::HttpRpcClient;
use ckb_sdk::{GenesisInfo, NetworkType};
use ckb_types::{
    core::{service::Request, BlockView, HeaderView},
    prelude::*,
    H256,
};
use ckb_util::RwLock;
use crossbeam_channel::{Receiver, Sender};
use serde_derive::{Deserialize, Serialize};

pub enum IndexRequest {
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
    epoch: u64,
    number: u64,
    hash: H256,
}

impl From<HeaderView> for SimpleBlockInfo {
    fn from(header: HeaderView) -> SimpleBlockInfo {
        SimpleBlockInfo {
            number: header.number(),
            epoch: header.epoch(),
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
    fn start_init(&mut self) {
        *self = IndexThreadState::StartInit;
    }
    fn processing(&mut self, header: Option<HeaderView>, tip_number: u64) {
        let block_info = header.map(Into::into);
        *self = IndexThreadState::Processing(block_info, tip_number);
    }
    fn error(&mut self, err: String) {
        *self = IndexThreadState::Error(err);
    }
    fn stop(&mut self) {
        *self = IndexThreadState::Stopped;
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

pub fn start_index_thread(
    url: &str,
    index_dir: PathBuf,
    state: Arc<RwLock<IndexThreadState>>,
) -> IndexController {
    let mut rpc_url = url.to_owned();
    let (sender, receiver) = crossbeam_channel::bounded::<Request<IndexRequest, IndexResponse>>(1);
    let shutdown = Arc::new(AtomicBool::new(false));
    let state_clone = Arc::clone(&state);
    let shutdown_clone = Arc::clone(&shutdown);

    thread::Builder::new()
        .name("index".to_string())
        .spawn(move || {
            loop {
                // Wait first request
                match try_recv(&receiver, &mut rpc_url) {
                    Some(true) => {
                        state.write().stop();
                        log::info!("Index database thread stopped");
                        return;
                    }
                    Some(false) => break,
                    None => thread::sleep(Duration::from_millis(100)),
                }
            }

            let mut rpc_client = HttpRpcClient::from_uri(rpc_url.as_str());
            loop {
                match process(
                    &receiver,
                    &mut rpc_url,
                    &mut rpc_client,
                    &index_dir,
                    &state,
                    &shutdown_clone,
                ) {
                    Ok(true) => {
                        state.write().stop();
                        log::info!("Index database thread stopped");
                        break;
                    }
                    Ok(false) => {}
                    Err(err) => {
                        state.write().error(err.clone());
                        log::info!("rpc call or db error: {:?}", err);
                        if shutdown_clone.load(Ordering::Relaxed) {
                            break;
                        }
                        thread::sleep(Duration::from_secs(2));
                    }
                }
            }
        })
        .expect("Spawn index thread failed");

    IndexController {
        state: state_clone,
        sender,
        shutdown,
    }
}

fn process(
    receiver: &Receiver<Request<IndexRequest, IndexResponse>>,
    rpc_url: &mut String,
    rpc_client: &mut HttpRpcClient,
    index_dir: &PathBuf,
    state: &Arc<RwLock<IndexThreadState>>,
    shutdown: &Arc<AtomicBool>,
) -> Result<bool, String> {
    let old_rpc_url = rpc_url.clone();
    if let Some(exit) = try_recv(&receiver, rpc_url) {
        return Ok(exit);
    }

    state.write().start_init();
    if &old_rpc_url != rpc_url {
        *rpc_client = HttpRpcClient::from_uri(rpc_url.as_str());
    }
    let genesis_block: BlockView = rpc_client
        .get_block_by_number(BlockNumber(0))
        .call()
        .map_err(|err| err.to_string())?
        .0
        .expect("Can not get genesis block?")
        .into();
    let genesis_info = GenesisInfo::from_block(&genesis_block).unwrap();
    let genesis_hash: H256 = genesis_info.header().hash().unpack();

    let mut next_get_tip = Instant::now();
    let mut tip_header = genesis_info.header().clone();
    let mut next_number = 0;
    loop {
        if next_get_tip <= Instant::now() {
            next_get_tip = Instant::now() + Duration::from_secs(1);
            tip_header = rpc_client
                .get_tip_header()
                .call()
                .map_err(|err| err.to_string())?
                .into();
            log::debug!("Update to tip {}", tip_header.number());
        }

        if tip_header.number() >= next_number {
            let exit_opt = with_index_db(index_dir, genesis_hash.clone(), |backend, cf| {
                let mut db = IndexDatabase::from_db(
                    backend,
                    cf,
                    NetworkType::TestNet,
                    genesis_info.clone(),
                    false,
                )
                .unwrap();
                if db.last_number().is_none() {
                    db.apply_next_block(genesis_block.clone())
                        .expect("Apply genesis block failed");
                }
                db.update_tip(tip_header.clone());
                while tip_header.number() > db.last_number().unwrap() {
                    if shutdown.load(Ordering::Relaxed) {
                        return Ok(Some(true));
                    }
                    if let Some(exit) = try_recv(&receiver, rpc_url) {
                        return Ok(Some(exit));
                    }
                    let next_block_number = BlockNumber(db.next_number().unwrap());
                    if let Some(next_block) = rpc_client
                        .get_block_by_number(next_block_number)
                        .call()
                        .map_err(|err| err.to_string())?
                        .0
                    {
                        db.apply_next_block(next_block.into())
                            .expect("Add block failed");
                        state
                            .write()
                            .processing(db.last_header().cloned(), tip_header.number());
                    } else {
                        log::warn!("fork happening, wait a second");
                        thread::sleep(Duration::from_secs(1));
                    }
                }
                next_number = db.last_number().unwrap() + 1;
                state
                    .write()
                    .processing(db.last_header().cloned(), tip_header.number());
                Ok(None)
            })
            .map_err(|err| err.to_string())?;
            if let Some(exit) = exit_opt {
                return Ok(exit);
            }
        }

        if shutdown.load(Ordering::Relaxed) {
            return Ok(true);
        }
        if let Some(exit) = try_recv(&receiver, rpc_url) {
            return Ok(exit);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn try_recv(
    receiver: &Receiver<Request<IndexRequest, IndexResponse>>,
    rpc_url: &mut String,
) -> Option<bool> {
    match receiver.try_recv() {
        Ok(request) => Some(process_request(request, rpc_url)),
        Err(err) => {
            if err.is_disconnected() {
                log::info!("Sender dropped, exit index thread");
                Some(true)
            } else {
                None
            }
        }
    }
}

fn process_request(request: Request<IndexRequest, IndexResponse>, rpc_url: &mut String) -> bool {
    let Request {
        responder,
        arguments,
    } = request;
    match arguments {
        IndexRequest::UpdateUrl(url) => {
            *rpc_url = url;
            responder.send(IndexResponse::Ok).is_err()
        }
    }
}
