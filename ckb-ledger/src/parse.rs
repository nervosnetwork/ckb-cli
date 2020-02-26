pub use super::error::Error;

pub fn split_off_at<'inner, 'outer>(
    response: &'outer mut &'inner [u8],
    idx: usize,
) -> Result<(&'inner [u8]), Error> {
    let (head, tail) = {
        let old_resp = *response;
        // TODO why no non-panicking split at....
        if old_resp.len() < idx {
            return Err(Error::RestOfResponseTooShort {
                expected: idx,
                tail: old_resp.to_vec(),
            });
        }
        old_resp.split_at(idx)
    };
    *response = tail;
    Ok(head)
}

pub fn split_first<'inner, 'outer>(
    response: &'outer mut &'inner [u8],
) -> Result<u8, Error> {
    let len_slice = split_off_at(response, 1)?;
    Ok(match *len_slice {
        [len] => len,
        _ => unreachable!("we used 1 above so this should be a 1-element slice"),
    })
}

pub fn assert_nothing_left(response: &[u8]) -> Result<(), Error> {
    if response.len() != 0 {
        Err(Error::TrailingExtraReponse {
            tail: response.to_vec(),
        })
    } else {
        Ok(())
    }
}
