use std::path::PathBuf;
use std::sync::Arc;

use ckb_index::IndexDatabase;
use ckb_sdk::{GenesisInfo, HttpRpcClient};
use ckb_types::{
    core::{service::Request, BlockView},
    prelude::*,
    H256,
};
use ckb_util::RwLock;
use clap::{App, ArgMatches};

use super::{CliSubCommand, Output};
use crate::utils::index::{with_db, IndexController, IndexRequest, IndexThreadState};

pub struct IndexSubCommand<'a> {
    rpc_client: &'a mut HttpRpcClient,
    genesis_info: Option<GenesisInfo>,
    index_dir: PathBuf,
    index_controller: IndexController,
    index_state: Arc<RwLock<IndexThreadState>>,
    wait_for_sync: bool,
}

impl<'a> IndexSubCommand<'a> {
    pub fn new(
        rpc_client: &'a mut HttpRpcClient,
        genesis_info: Option<GenesisInfo>,
        index_dir: PathBuf,
        index_controller: IndexController,
        index_state: Arc<RwLock<IndexThreadState>>,
        wait_for_sync: bool,
    ) -> IndexSubCommand<'a> {
        IndexSubCommand {
            rpc_client,
            genesis_info,
            index_dir,
            index_controller,
            index_state,
            wait_for_sync,
        }
    }

    pub fn subcommand(name: &'static str) -> App<'static> {
        App::new(name)
            .about("Index database management")
            .subcommands(vec![
                App::new("db-metrics").about("Show index database metrics"),
                App::new("current-database-info")
                    .about("Show current index database's basic information"),
                App::new("rebuild-current-database")
                    .about("Remove and rebuild current index database"),
            ])
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
            self.rpc_client,
            genesis_info,
            &self.index_dir,
            self.index_controller.clone(),
            self.wait_for_sync,
        )
    }

    fn db_dir(&mut self) -> Result<PathBuf, String> {
        let genesis_info = self.genesis_info()?;
        let genesis_hash: H256 = genesis_info.header().hash().unpack();
        Ok(self.index_dir.join(format!("{:#x}", genesis_hash)))
    }
}

impl<'a> CliSubCommand for IndexSubCommand<'a> {
    fn process(&mut self, matches: &ArgMatches, _debug: bool) -> Result<Output, String> {
        match matches.subcommand() {
            ("current-database-info", _) => Ok(Output::new_output(serde_json::json!({
                "directory": self.db_dir()?.to_string_lossy(),
                "state": self.index_state.read().to_string(),
            }))),
            ("rebuild-current-database", _) => {
                Request::call(
                    self.index_controller.sender(),
                    IndexRequest::RebuildCurrentDB,
                );
                Ok(Output::new_success())
            }
            ("db-metrics", _) => {
                let metrcis = self.with_db(|db| db.get_metrics(None))?;
                let resp = serde_json::to_value(metrcis).map_err(|err| err.to_string())?;
                Ok(Output::new_output(resp))
            }
            _ => Err(Self::subcommand("index").generate_usage()),
        }
    }
}
