use ledger::ApduCommand;

pub fn app_version() -> ledger::ApduCommand {
    ApduCommand {
        cla: 0x80,
        ins: 0x00,
        p1: 0x00,
        p2: 0x00,
        length: 0,
        data: Vec::new(),
    }
}

pub fn app_git_hash() -> ledger::ApduCommand {
    ApduCommand {
        cla: 0x80,
        ins: 0x09,
        p1: 0x00,
        p2: 0x00,
        length: 0,
        data: Vec::new(),
    }
}

pub fn extend_public_key(data: Vec<u8>) -> ledger::ApduCommand {
    ApduCommand {
        cla: 0x80,
        ins: 0x02,
        p1: 0x00,
        p2: 0x00,
        length: data.len() as u8,
        data,
    }
}

pub fn get_wallet_id() -> ledger::ApduCommand {
    ApduCommand {
        cla: 0x80,
        ins: 0x01,
        p1: 0x00,
        p2: 0x00,
        length: 0,
        data: Vec::new(),
    }
}
