use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ckb_core::{header::Header as CoreHeader, service::Request};
use ckb_sdk::{Address, NetworkType};
use ckb_util::RwLock;
use crossbeam_channel::{Receiver, Sender};
use jsonrpc_types::{BlockNumber, HeaderView};
use numext_fixed_hash::H256;
use serde_derive::{Deserialize, Serialize};

use ckb_sdk::rpc::HttpRpcClient;
use ckb_sdk::{KeyMetrics, KeyType, LiveCellDatabase, LiveCellInfo};

pub enum IndexRequest {
    UpdateUrl(String),
    GetLiveCellInfos {
        address: Address,
        total_capacity: u64,
    },
    GetTopLocks(usize),
    GetCapacity(H256),
    GetBalance(Address),
    GetMetrics,
    // GetLastHeader,
    // RebuildIndex,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IndexResponse {
    LiveCellInfos {
        infos: Vec<LiveCellInfo>,
        total_capacity: u64,
        last_block: SimpleBlockInfo,
    },
    TopLocks {
        capacity_list: Vec<CapacityResult>,
        last_block: SimpleBlockInfo,
    },
    Capacity {
        capacity: Option<u64>,
        // live_cell_count: Option<usize>,
        last_block: SimpleBlockInfo,
    },
    LastHeader(CoreHeader),
    DatabaseMetrics(BTreeMap<KeyType, KeyMetrics>),
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

impl From<CoreHeader> for SimpleBlockInfo {
    fn from(header: CoreHeader) -> SimpleBlockInfo {
        SimpleBlockInfo {
            number: header.number(),
            epoch: header.epoch(),
            hash: header.hash().clone(),
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
    Processing(SimpleBlockInfo, u64),
    // Thread exit
    Stopped,
}

impl IndexThreadState {
    fn start_init(&mut self) {
        *self = IndexThreadState::StartInit;
    }
    fn processing(&mut self, header: CoreHeader, tip_number: u64) {
        *self = IndexThreadState::Processing(header.into(), tip_number);
    }
    fn stop(&mut self) {
        *self = IndexThreadState::Stopped;
    }
    pub fn is_stopped(&self) -> bool {
        match self {
            IndexThreadState::Stopped => true,
            _ => false,
        }
    }
    pub fn is_processing(&self) -> bool {
        match self {
            IndexThreadState::Processing(_, _) => true,
            _ => false,
        }
    }
}

impl fmt::Display for IndexThreadState {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        let output = match self {
            IndexThreadState::WaitToStart => "waiting for first query".to_owned(),
            IndexThreadState::StartInit => "initializating".to_owned(),
            IndexThreadState::Processing(SimpleBlockInfo { number, .. }, tip_number) => {
                format!("processed block#{} (tip#{})", number, tip_number)
            }
            IndexThreadState::Stopped => "stopped".to_owned(),
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
}

impl Clone for IndexController {
    fn clone(&self) -> IndexController {
        IndexController {
            state: Arc::clone(&self.state),
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
        let _ = Request::call(&self.sender, IndexRequest::Shutdown);
        while !self.state().read().is_stopped() {
            if start_time.elapsed() < Duration::from_secs(10) {
                thread::sleep(Duration::from_millis(50));
            } else {
                eprintln!("Stop index thread timeout, give up");
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
    let state_clone = Arc::clone(&state);

    thread::spawn(move || {
        let mut first_request = match receiver.recv() {
            Ok(request) => match request.arguments {
                IndexRequest::UpdateUrl(ref url) => {
                    rpc_url = url.clone();
                    if let Err(err) = request.responder.send(IndexResponse::Ok) {
                        log::debug!("response first change url failed {:?}", err);
                        return;
                    };
                    None
                }
                IndexRequest::Shutdown => {
                    state.write().stop();
                    return;
                }
                _ => Some(request),
            },
            Err(err) => {
                log::debug!("index db receiver error: {:?}", err);
                None
            }
        };
        state.write().start_init();
        let mut rpc_client = HttpRpcClient::from_uri(rpc_url.as_str());
        let genesis_block = rpc_client
            .get_block_by_number(BlockNumber(0))
            .call()
            .unwrap()
            .0
            .unwrap();
        let mut db =
            LiveCellDatabase::from_path(NetworkType::TestNet, &genesis_block, index_dir.clone())
                .unwrap();

        let mut last_get_tip = Instant::now();
        let mut tip_header = rpc_client.get_tip_header().call().unwrap();
        db.update_tip(tip_header.clone());

        loop {
            if last_get_tip.elapsed() > Duration::from_secs(2) {
                last_get_tip = Instant::now();
                tip_header = rpc_client.get_tip_header().call().unwrap();
                db.update_tip(tip_header.clone());
                log::debug!("Update to tip {}", tip_header.inner.number.0);
            }

            while tip_header.inner.number.0.saturating_sub(4) > db.last_number() {
                if try_recv(
                    &receiver,
                    &mut db,
                    &index_dir,
                    &mut tip_header,
                    &mut rpc_client,
                ) {
                    state.write().stop();
                    break;
                }
                let next_block = rpc_client
                    .get_block_by_number(db.next_number())
                    .call()
                    .unwrap()
                    .0
                    .unwrap();
                db.apply_next_block(&next_block).expect("Add block failed");
                state
                    .write()
                    .processing(db.last_header().clone(), tip_header.inner.number.0);
            }

            if first_request
                .take()
                .map(|request| {
                    process_request(
                        request,
                        &mut db,
                        &index_dir,
                        &mut tip_header,
                        &mut rpc_client,
                    )
                })
                .unwrap_or(false)
            {
                state.write().stop();
            }
            if try_recv(
                &receiver,
                &mut db,
                &index_dir,
                &mut tip_header,
                &mut rpc_client,
            ) {
                state.write().stop();
            }

            if state.read().is_stopped() {
                break;
            }

            thread::sleep(Duration::from_millis(100));
        }

        state.write().stop();
        log::info!("Index database thread stopped");
    });

    IndexController {
        state: state_clone,
        sender,
    }
}

fn try_recv(
    receiver: &Receiver<Request<IndexRequest, IndexResponse>>,
    db: &mut LiveCellDatabase,
    index_dir: &PathBuf,
    tip_header: &mut HeaderView,
    rpc_client: &mut HttpRpcClient,
) -> bool {
    match receiver.try_recv() {
        Ok(request) => process_request(request, db, index_dir, tip_header, rpc_client),
        Err(err) => {
            if err.is_disconnected() {
                log::info!("Sender dropped, exit index thread");
                true
            } else {
                false
            }
        }
    }
}

fn process_request(
    request: Request<IndexRequest, IndexResponse>,
    db: &mut LiveCellDatabase,
    index_dir: &PathBuf,
    tip_header: &mut HeaderView,
    rpc_client: &mut HttpRpcClient,
) -> bool {
    let Request {
        responder,
        arguments,
    } = request;
    match arguments {
        IndexRequest::UpdateUrl(url) => {
            *rpc_client = HttpRpcClient::from_uri(url.as_str());
            let genesis_block = rpc_client
                .get_block_by_number(BlockNumber(0))
                .call()
                .unwrap()
                .0
                .unwrap();
            *db = LiveCellDatabase::from_path(
                NetworkType::TestNet,
                &genesis_block,
                index_dir.clone(),
            )
            .unwrap();
            *tip_header = rpc_client.get_tip_header().call().unwrap();
            db.update_tip(tip_header.clone());
            responder.send(IndexResponse::Ok).is_err()
        }
        IndexRequest::GetLiveCellInfos {
            address,
            total_capacity,
        } => {
            let lock_hash = address.lock_script().hash();
            let (infos, total_capacity) = db.get_live_cell_infos(lock_hash, total_capacity);
            responder
                .send(IndexResponse::LiveCellInfos {
                    infos,
                    total_capacity,
                    last_block: db.last_header().clone().into(),
                })
                .is_err()
        }
        IndexRequest::GetTopLocks(n) => responder
            .send(IndexResponse::TopLocks {
                capacity_list: db
                    .get_top_n(n)
                    .into_iter()
                    .map(|(lock_hash, address, capacity)| {
                        let address = address.map(|addr| addr.to_string(NetworkType::TestNet));
                        CapacityResult {
                            lock_hash,
                            address,
                            capacity,
                        }
                    })
                    .collect::<Vec<_>>(),
                last_block: db.last_header().clone().into(),
            })
            .is_err(),

        IndexRequest::GetCapacity(lock_hash) => {
            responder
                .send(IndexResponse::Capacity {
                    capacity: db.get_capacity(lock_hash),
                    // live_cell_count: result.map(|value| value.1),
                    last_block: db.last_header().clone().into(),
                })
                .is_err()
        }
        IndexRequest::GetBalance(address) => {
            let lock_hash = address.lock_script().hash();
            responder
                .send(IndexResponse::Capacity {
                    capacity: db.get_capacity(lock_hash),
                    // live_cell_count: result.map(|value| value.1),
                    last_block: db.last_header().clone().into(),
                })
                .is_err()
        }

        IndexRequest::GetMetrics => responder
            .send(IndexResponse::DatabaseMetrics(db.get_metrics(None)))
            .is_err(),
        // IndexRequest::GetLastHeader => responder
        //     .send(IndexResponse::LastHeader(db.last_header().clone()))
        //     .is_err(),
        // IndexRequest::RebuildIndex => responder.send(IndexResponse::Ok).is_err(),
        IndexRequest::Shutdown => {
            let _ = responder.send(IndexResponse::Ok);
            log::info!("Received shutdown message");
            true
        }
    }
}
