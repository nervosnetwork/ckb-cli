use std::fs;
use std::io::Read;
use std::str::FromStr;

use crypto::secp::Privkey;

pub fn privkey_from_file(path: &str) -> Result<Privkey, String> {
    let mut content = String::new();
    let mut file = fs::File::open(path).map_err(|err| err.to_string())?;
    file.read_to_string(&mut content)
        .map_err(|err| err.to_string())?;
    let privkey_string: String = content
        .split_whitespace()
        .next()
        .map(|s| s.to_owned())
        .ok_or_else(|| "File is empty".to_string())?;
    let privkey_str = if privkey_string.starts_with("0x") || privkey_string.starts_with("0X") {
        &privkey_string[2..]
    } else {
        privkey_string.as_str()
    };
    Privkey::from_str(privkey_str.trim()).map_err(|err| err.to_string())
}
