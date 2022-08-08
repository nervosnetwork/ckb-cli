use ckb_sdk::traits::DefaultCellDepResolver;
use ckb_types::{
    core::{BlockView, HeaderView},
    packed::CellDep,
};

#[derive(Clone)]
pub struct GenesisInfo {
    pub cell_dep_resolver: DefaultCellDepResolver,
    pub genesis_header: HeaderView,
}

impl GenesisInfo {
    pub fn from_block(block: &BlockView) -> Result<GenesisInfo, String> {
        let cell_dep_resolver =
            DefaultCellDepResolver::from_genesis(block).map_err(|err| err.to_string())?;
        let genesis_header = block.header();
        Ok(GenesisInfo {
            cell_dep_resolver,
            genesis_header,
        })
    }

    pub fn sighash_dep(&self) -> CellDep {
        self.cell_dep_resolver.sighash_dep().unwrap().0.clone()
    }
    pub fn multisig_dep(&self) -> CellDep {
        self.cell_dep_resolver.multisig_dep().unwrap().0.clone()
    }
    pub fn dao_dep(&self) -> CellDep {
        self.cell_dep_resolver.dao_dep().unwrap().0.clone()
    }
}
