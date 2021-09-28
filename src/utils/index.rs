use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use super::other::{get_network_type, sync_to_tip};
use ckb_index::{with_index_db, CellIndex, IndexDatabase, LiveCellInfo};
use ckb_jsonrpc_types::{BlockNumber, JsonBytes, Uint32};
use ckb_sdk::rpc::ckb_indexer::{
    Cell, IndexerRpcClient, Order, ScriptType, SearchKey, SearchKeyFilter, Tip,
};
use ckb_sdk::{AddressPayload, GenesisInfo, HttpRpcClient};
use ckb_types::{
    core::{service::Request, BlockView, HeaderView, ScriptHashType},
    packed::{Byte32, Script},
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
        !matches!(self, IndexThreadState::WaitToStart)
    }
    pub fn is_stopped(&self) -> bool {
        matches!(self, IndexThreadState::Stopped)
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
        matches!(self, IndexThreadState::Error(_))
    }
    #[cfg_attr(windows, allow(dead_code))]
    pub fn is_processing(&self) -> bool {
        matches!(self, IndexThreadState::Processing(Some(_), _))
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
    index_dir: &Path,
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

pub trait Indexer {
    fn get_top_n(&mut self, n: usize)
        -> Result<Vec<(Byte32, Option<AddressPayload>, u64)>, String>;
    fn get_capacity(&mut self, lock: Script) -> Result<Option<u64>, String>;
    // By code hash
    fn get_live_cells_by_code_hash(
        &mut self,
        code_hash: Byte32,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String>;
    // By type script hash
    fn get_live_cells_by_type_hash(
        &mut self,
        type_hash: Byte32,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String>;
    // By lock script hash
    fn get_live_cells_by_lock_hash(
        &mut self,
        lock_hash: Byte32,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String>;

    // By type script
    fn get_live_cells_by_type_script(
        &mut self,
        type_script: Script,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String>;
    // By lock script
    fn get_live_cells_by_lock_script(
        &mut self,
        lock: Script,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String>;
}

pub struct LocalIndexer {
    pub index_dir: PathBuf,
    pub index_controller: IndexController,
    pub rpc_client: HttpRpcClient,
    pub genesis_info: Option<GenesisInfo>,
    pub wait_for_sync: bool,
}

impl Clone for LocalIndexer {
    fn clone(&self) -> LocalIndexer {
        LocalIndexer {
            index_dir: self.index_dir.clone(),
            index_controller: self.index_controller.clone(),
            rpc_client: HttpRpcClient::new(self.rpc_client.url().to_string()),
            genesis_info: self.genesis_info.clone(),
            wait_for_sync: self.wait_for_sync,
        }
    }
}

impl LocalIndexer {
    pub fn new(
        index_dir: PathBuf,
        index_controller: IndexController,
        rpc_client: HttpRpcClient,
        genesis_info: Option<GenesisInfo>,
        wait_for_sync: bool,
    ) -> LocalIndexer {
        LocalIndexer {
            index_dir,
            index_controller,
            rpc_client,
            genesis_info,
            wait_for_sync,
        }
    }

    fn genesis_info(&mut self) -> Result<GenesisInfo, String> {
        if self.genesis_info.is_none() {
            let genesis_block: BlockView = self
                .rpc_client
                .get_block_by_number(0)?
                .expect("Can not get genesis block?")
                .into();
            self.genesis_info = Some(GenesisInfo::from_block(&genesis_block)?);
        }
        Ok(self.genesis_info.clone().unwrap())
    }

    fn with_db<F, T>(&mut self, func: F) -> Result<T, String>
    where
        F: FnOnce(IndexDatabase) -> T,
    {
        let genesis_info = self.genesis_info()?;
        with_db(
            func,
            &mut self.rpc_client,
            genesis_info,
            &self.index_dir,
            self.index_controller.clone(),
            self.wait_for_sync,
        )
    }
}

impl Indexer for LocalIndexer {
    fn get_top_n(
        &mut self,
        n: usize,
    ) -> Result<Vec<(Byte32, Option<AddressPayload>, u64)>, String> {
        self.with_db(|db| db.get_top_n(n))
    }
    fn get_capacity(&mut self, lock: Script) -> Result<Option<u64>, String> {
        let lock_hash = lock.calc_script_hash();
        self.with_db(|db| db.get_capacity(lock_hash))
    }

    // By code hash
    fn get_live_cells_by_code_hash(
        &mut self,
        code_hash: Byte32,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        self.with_db(|db| db.get_live_cells_by_code(code_hash, from_number, terminator))
    }
    // By type script hash
    fn get_live_cells_by_type_hash(
        &mut self,
        type_hash: Byte32,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        self.with_db(|db| db.get_live_cells_by_type(type_hash, from_number, terminator))
    }
    // By lock script hash
    fn get_live_cells_by_lock_hash(
        &mut self,
        lock_hash: Byte32,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        self.with_db(|db| db.get_live_cells_by_lock(lock_hash, from_number, terminator))
    }

    // By type script
    fn get_live_cells_by_type_script(
        &mut self,
        type_script: Script,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        let type_hash = type_script.calc_script_hash();
        self.with_db(|db| db.get_live_cells_by_type(type_hash, from_number, terminator))
    }
    // By lock script
    fn get_live_cells_by_lock_script(
        &mut self,
        lock: Script,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        let lock_hash = lock.calc_script_hash();
        self.with_db(|db| db.get_live_cells_by_lock(lock_hash, from_number, terminator))
    }
}

pub struct RemoteIndexer {
    pub indexer_client: IndexerRpcClient,
    pub rpc_client: HttpRpcClient,
}

impl Clone for RemoteIndexer {
    fn clone(&self) -> RemoteIndexer {
        RemoteIndexer {
            indexer_client: IndexerRpcClient::new(self.indexer_client.url.as_str()),
            rpc_client: HttpRpcClient::new(self.rpc_client.url().to_string()),
        }
    }
}

impl RemoteIndexer {
    pub fn new(ckb_indexer_url: &str, rpc_client: HttpRpcClient) -> RemoteIndexer {
        let indexer_client = IndexerRpcClient::new(ckb_indexer_url);
        RemoteIndexer {
            indexer_client,
            rpc_client,
        }
    }

    pub fn check_ckb_chain(&mut self) -> Result<(), String> {
        let tip_header = self.rpc_client.get_tip_header()?;
        let tip_hash = tip_header.hash;
        let tip_number = tip_header.inner.number;
        let mut retry = 10;
        while retry > 0 {
            match self
                .indexer_client
                .get_tip()
                .map_err(|err| err.to_string())?
            {
                Some(Tip {
                    block_hash,
                    block_number,
                }) => {
                    if tip_number > block_number.value() {
                        log::info!("ckb-indexer not ready, wait for 50ms");
                        thread::sleep(Duration::from_millis(50));
                        retry -= 1;
                        continue;
                    } else if tip_hash == block_hash && tip_number == block_number.value() {
                        log::info!("ckb-indexer ready!");
                        return Ok(());
                    } else {
                        log::info!("ckb-indexer server inconsistent with currently connected ckb node or not synced!");
                        return Err("ckb-indexer server inconsistent with currently connected ckb node or not synced!".to_owned());
                    }
                }
                None => {
                    log::info!("ckb-indexer server not synced");
                    return Err("ckb-indexer server not synced".to_owned());
                }
            }
        }
        log::info!("wait for ckb-indexer timeout(500ms)");
        Err(
            "ckb-indexer server inconsistent with currently connected ckb node or not synced!"
                .to_owned(),
        )
    }

    fn get_live_cells<F: FnMut(usize, &LiveCellInfo) -> (bool, bool)>(
        &mut self,
        search_key: SearchKey,
        mut terminator: F,
    ) -> Result<(bool, Vec<LiveCellInfo>), String> {
        self.check_ckb_chain()?;
        let mut limit = 128;
        let max_limit = 4096;
        let mut idx = 0;
        let mut last_cursor: Option<JsonBytes> = None;
        let mut infos = Vec::new();
        let mut finished = false;
        loop {
            let page = self
                .indexer_client
                .get_cells(
                    search_key.clone(),
                    Order::Asc,
                    Uint32::from(limit),
                    last_cursor,
                )
                .map_err(|err| err.to_string())?;
            if page.objects.is_empty() {
                break;
            }
            for cell in page.objects {
                let live_cell_info = to_live_cell_info(cell);
                let (stop, push_info) = terminator(idx, &live_cell_info);
                if push_info {
                    infos.push(live_cell_info);
                }
                if stop {
                    finished = true;
                    break;
                }
                idx += 1;
            }
            if finished {
                break;
            }
            last_cursor = Some(page.last_cursor);
            if limit < max_limit {
                // limit *= 2;
                limit <<= 1;
            }
        }
        Ok((finished, infos))
    }
}

impl Indexer for RemoteIndexer {
    fn get_top_n(
        &mut self,
        _n: usize,
    ) -> Result<Vec<(Byte32, Option<AddressPayload>, u64)>, String> {
        log::info!("get_top_n not support by ckb-indexer");
        Err("Not support by ckb-indexer".to_owned())
    }
    fn get_capacity(&mut self, lock: Script) -> Result<Option<u64>, String> {
        self.check_ckb_chain()?;
        let search_key = SearchKey {
            script: lock.into(),
            script_type: ScriptType::Lock,
            filter: None,
        };
        self.indexer_client
            .get_cells_capacity(search_key)
            .map(|opt| opt.map(|cap| cap.capacity.value()))
            .map_err(|err| err.to_string())
    }

    // By code hash
    fn get_live_cells_by_code_hash(
        &mut self,
        code_hash: Byte32,
        from_number: Option<u64>,
        mut terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        let filter = from_number.map(|number| SearchKeyFilter {
            script: None,
            output_data_len_range: None,
            output_capacity_range: None,
            block_range: Some([
                BlockNumber::from(number),
                BlockNumber::from(u64::max_value()),
            ]),
        });
        let mut all_infos = Vec::new();
        for script_type in &[ScriptType::Type, ScriptType::Lock] {
            for hash_type in &[
                ScriptHashType::Type,
                ScriptHashType::Data,
                ScriptHashType::Data1,
            ] {
                let script = Script::new_builder()
                    .code_hash(code_hash.clone())
                    .hash_type((*hash_type).into())
                    .build();
                let search_key = SearchKey {
                    script: script.into(),
                    script_type: script_type.clone(),
                    filter: filter.clone(),
                };
                let (finished, infos) = self.get_live_cells(search_key, &mut terminator)?;
                all_infos.extend(infos);
                if finished {
                    return Ok(all_infos);
                }
            }
        }
        Ok(all_infos)
    }
    // By type script hash
    fn get_live_cells_by_type_hash(
        &mut self,
        _type_hash: Byte32,
        _from_number: Option<u64>,
        _terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        log::info!("get_live_cells_by_type_hash not support by ckb-indexer");
        Err("Not support by ckb-indexer".to_owned())
    }
    // By lock script hash
    fn get_live_cells_by_lock_hash(
        &mut self,
        _lock_hash: Byte32,
        _from_number: Option<u64>,
        _terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        log::info!("get_live_cells_by_lock_hash not support by ckb-indexer");
        Err("Not support by ckb-indexer".to_owned())
    }

    // By type script
    fn get_live_cells_by_type_script(
        &mut self,
        type_script: Script,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        let filter = from_number.map(|number| SearchKeyFilter {
            script: None,
            output_data_len_range: None,
            output_capacity_range: None,
            block_range: Some([
                BlockNumber::from(number),
                BlockNumber::from(u64::max_value()),
            ]),
        });
        let search_key = SearchKey {
            script: type_script.into(),
            script_type: ScriptType::Type,
            filter,
        };
        self.get_live_cells(search_key, terminator)
            .map(|(_, infos)| infos)
    }
    // By lock script
    fn get_live_cells_by_lock_script(
        &mut self,
        lock: Script,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        let filter = from_number.map(|number| SearchKeyFilter {
            script: None,
            output_data_len_range: None,
            output_capacity_range: None,
            block_range: Some([
                BlockNumber::from(number),
                BlockNumber::from(u64::max_value()),
            ]),
        });
        let search_key = SearchKey {
            script: lock.into(),
            script_type: ScriptType::Lock,
            filter,
        };
        self.get_live_cells(search_key, terminator)
            .map(|(_, infos)| infos)
    }
}

#[derive(Clone)]
pub struct CommonIndexer {
    local: LocalIndexer,
    remote: Option<RemoteIndexer>,
}

impl CommonIndexer {
    pub fn new(local: LocalIndexer, remote: Option<RemoteIndexer>) -> CommonIndexer {
        CommonIndexer { local, remote }
    }
    pub fn local(&self) -> &LocalIndexer {
        &self.local
    }
    pub fn remote(&self) -> Option<&RemoteIndexer> {
        self.remote.as_ref()
    }
    pub fn set_ckb_indexer_url(&mut self, url: &str) {
        if url.is_empty() || url == "disable" {
            self.remote = None;
        } else {
            self.remote = Some(RemoteIndexer::new(
                url,
                HttpRpcClient::new(self.local.rpc_client.url().to_string()),
            ));
        }
    }
    pub fn set_ckb_rpc_url(&mut self, url: String) {
        self.local.rpc_client = HttpRpcClient::new(url.clone());
        self.local.genesis_info = None;
        if let Some(remote) = self.remote.as_mut() {
            remote.rpc_client = HttpRpcClient::new(url);
        }
    }
    pub fn set_genesis_info(&mut self, info_opt: Option<GenesisInfo>) {
        self.local.genesis_info = info_opt;
    }
    pub fn set_wait_for_sync(&mut self, wait_for_sync: bool) {
        self.local.wait_for_sync = wait_for_sync;
    }
}

impl Indexer for CommonIndexer {
    fn get_top_n(
        &mut self,
        n: usize,
    ) -> Result<Vec<(Byte32, Option<AddressPayload>, u64)>, String> {
        self.local.get_top_n(n)
    }
    fn get_capacity(&mut self, lock: Script) -> Result<Option<u64>, String> {
        if let Some(Ok(result)) = self
            .remote
            .as_mut()
            .map(|client| client.get_capacity(lock.clone()))
        {
            Ok(result)
        } else {
            self.local.get_capacity(lock)
        }
    }
    // By code hash
    fn get_live_cells_by_code_hash(
        &mut self,
        code_hash: Byte32,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        if let Some(Ok(result)) = self.remote.as_mut().map(|client| {
            client.get_live_cells_by_code_hash(code_hash.clone(), from_number, terminator)
        }) {
            Ok(result)
        } else {
            self.local
                .get_live_cells_by_code_hash(code_hash, from_number, terminator)
        }
    }
    // By type script hash
    fn get_live_cells_by_type_hash(
        &mut self,
        type_hash: Byte32,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        log::info!("get_live_cells_by_type_hash by lock index database");
        self.local
            .get_live_cells_by_type_hash(type_hash, from_number, terminator)
    }
    // By lock script hash
    fn get_live_cells_by_lock_hash(
        &mut self,
        lock_hash: Byte32,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        log::info!("get_live_cells_by_lock_hash by lock index database");
        self.local
            .get_live_cells_by_lock_hash(lock_hash, from_number, terminator)
    }

    // By type script
    fn get_live_cells_by_type_script(
        &mut self,
        type_script: Script,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        if let Some(Ok(result)) = self.remote.as_mut().map(|client| {
            client.get_live_cells_by_type_script(type_script.clone(), from_number, terminator)
        }) {
            Ok(result)
        } else {
            self.local
                .get_live_cells_by_type_script(type_script, from_number, terminator)
        }
    }
    // By lock script
    fn get_live_cells_by_lock_script(
        &mut self,
        lock: Script,
        from_number: Option<u64>,
        terminator: &mut dyn FnMut(usize, &LiveCellInfo) -> (bool, bool),
    ) -> Result<Vec<LiveCellInfo>, String> {
        if let Some(Ok(result)) = self.remote.as_mut().map(|client| {
            client.get_live_cells_by_lock_script(lock.clone(), from_number, terminator)
        }) {
            Ok(result)
        } else {
            self.local
                .get_live_cells_by_lock_script(lock, from_number, terminator)
        }
    }
}

fn to_live_cell_info(cell: Cell) -> LiveCellInfo {
    let lock_hash: H256 = Script::from(cell.output.lock).calc_script_hash().unpack();
    let type_hashes = cell.output.type_.map(|script| {
        let code_hash = script.code_hash.clone();
        let script_hash: H256 = Script::from(script).calc_script_hash().unpack();
        (code_hash, script_hash)
    });
    LiveCellInfo {
        tx_hash: cell.out_point.tx_hash,
        output_index: cell.out_point.index.value(),
        data_bytes: cell.output_data.len() as u64,
        lock_hash,
        type_hashes,
        capacity: cell.output.capacity.value(),
        number: cell.block_number.value(),
        index: CellIndex {
            tx_index: cell.tx_index.value(),
            output_index: cell.out_point.index.value(),
        },
    }
}
