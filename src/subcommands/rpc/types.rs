use std::rc::Rc;

use jsonrpc_types::BlockNumber;
use numext_fixed_hash::H256;
use serde_json::to_string_pretty;

use ckb_sdk::rpc::{
    CellOutputWithOutPoints, CellWithStatus, ChainInfo, EpochExt, HeaderView, Node, Nodes,
    OptionBlockView, OptionEpochExt, OptionH256, OptionTransactionWithStatus, TxPoolInfo,
};

use crate::utils::printer::{OutputFormat, Printable};

// FIXME: Implement printable

impl Printable for BlockNumber {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for H256 {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for Node {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for ChainInfo {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for Nodes {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for TxPoolInfo {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for OptionTransactionWithStatus {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for CellOutputWithOutPoints {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for CellWithStatus {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for HeaderView {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for EpochExt {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for OptionBlockView {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for OptionH256 {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}

impl Printable for OptionEpochExt {
    fn rc_string(&self, _format: OutputFormat, _color: bool) -> Rc<String> {
        Rc::new(to_string_pretty(&self).unwrap())
    }
}
