use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use ckb_index::{with_index_db, Error, IndexDatabase, IndexError};
use ckb_sdk::GenesisInfo;
use ckb_sdk::HttpRpcClient;
use ckb_types::{
    core::{service::Request, BlockView},
    prelude::*,
    H256,
};
use ckb_util::RwLock;
use crossbeam_channel::Receiver;

use crate::utils::index::{IndexController, IndexRequest, IndexResponse, IndexThreadState};
use crate::utils::other::get_network_type;

pub fn start_index_thread(
    url: &str,
    index_dir: PathBuf,
    state: Arc<RwLock<IndexThreadState>>,
) -> IndexController {
    let (sender, receiver) = crossbeam_channel::bounded::<Request<IndexRequest, IndexResponse>>(1);
    let shutdown = Arc::new(AtomicBool::new(false));
    let state_clone = Arc::clone(&state);
    let shutdown_clone = Arc::clone(&shutdown);
    let mut rpc_client = HttpRpcClient::new(url.to_owned());

    thread::Builder::new()
        .name("index".to_string())
        .spawn(move || {
            loop {
                // Wait first request
                match try_recv(&receiver, &mut rpc_client) {
                    Some(true) => {
                        state.write().stop();
                        log::info!("Index database thread stopped");
                        return;
                    }
                    Some(false) => break,
                    None => thread::sleep(Duration::from_millis(100)),
                }
            }

            loop {
                match process(
                    &receiver,
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

    IndexController::new(state_clone, sender, shutdown)
}

fn process(
    receiver: &Receiver<Request<IndexRequest, IndexResponse>>,
    rpc_client: &mut HttpRpcClient,
    index_dir: &PathBuf,
    state: &Arc<RwLock<IndexThreadState>>,
    shutdown: &Arc<AtomicBool>,
) -> Result<bool, String> {
    if let Some(exit) = try_recv(&receiver, rpc_client) {
        return Ok(exit);
    }

    state.write().start_init();
    let genesis_block: BlockView = rpc_client
        .get_block_by_number(0)?
        .expect("Can not get genesis block?")
        .into();
    let network_type = get_network_type(rpc_client)?;
    let genesis_info = GenesisInfo::from_block(&genesis_block).unwrap();
    let genesis_hash: H256 = genesis_info.header().hash().unpack();

    let mut next_get_tip = Instant::now();
    let mut tip_header = genesis_info.header().clone();
    let mut next_number = 0;
    loop {
        if next_get_tip <= Instant::now() {
            next_get_tip = Instant::now() + Duration::from_secs(1);
            tip_header = rpc_client.get_tip_header()?.into();
            log::debug!("Update to tip {}", tip_header.number());
        }

        if tip_header.number() >= next_number {
            match with_index_db(index_dir, genesis_hash.clone(), |backend, cf| {
                let mut db =
                    IndexDatabase::from_db(backend, cf, network_type, genesis_info.clone(), false)
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
                    if let Some(exit) = try_recv(&receiver, rpc_client) {
                        return Ok(Some(exit));
                    }
                    if let Some(next_block) =
                        rpc_client.get_block_by_number(db.next_number().unwrap())?
                    {
                        db.apply_next_block(next_block.into())?;
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
            }) {
                Ok(Some(exit)) => {
                    return Ok(exit);
                }
                Ok(None) => {}
                Err(Error::Index(IndexError::LongFork)) => {
                    log::error!(
                        "\n{}!\nIf you running a dev chain and have removed the database directory (\"ckb/data/db\"), please also remove ckb-cli's index directory:\n  {:?}",
                        IndexError::LongFork,
                        index_dir.join(format!("{:#x}", genesis_hash))
                    );
                    return Ok(true);
                }
                Err(err) => {
                    return Err(err.to_string());
                }
            }
        }

        if shutdown.load(Ordering::Relaxed) {
            return Ok(true);
        }
        if let Some(exit) = try_recv(&receiver, rpc_client) {
            return Ok(exit);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn try_recv(
    receiver: &Receiver<Request<IndexRequest, IndexResponse>>,
    rpc_client: &mut HttpRpcClient,
) -> Option<bool> {
    match receiver.try_recv() {
        Ok(request) => Some(process_request(request, rpc_client)),
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

fn process_request(
    request: Request<IndexRequest, IndexResponse>,
    rpc_client: &mut HttpRpcClient,
) -> bool {
    let Request {
        responder,
        arguments,
    } = request;
    match arguments {
        IndexRequest::UpdateUrl(url) => {
            if url != rpc_client.url() {
                *rpc_client = HttpRpcClient::new(url);
            }
            responder.send(IndexResponse::Ok).is_err()
        }
        IndexRequest::Kick => false,
    }
}
