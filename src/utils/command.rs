#![allow(dead_code)]

use clap::Command;

pub trait CommandHelpExt {
    fn help(self, about: impl Into<String>) -> Self;
}

impl CommandHelpExt for Command {
    fn help(self, about: impl Into<String>) -> Self {
        self.about(about.into())
    }
}
