pub(crate) fn put_pair(
    store: &rkv::SingleStore,
    writer: &mut rkv::Writer,
    (key, value): (Vec<u8>, Vec<u8>),
) {
    store.put(writer, key, &rkv::Value::Blob(&value)).unwrap();
}

pub(crate) fn value_to_bytes<'a>(value: &'a rkv::Value) -> &'a [u8] {
    match value {
        rkv::Value::Blob(inner) => inner,
        _ => panic!("Invalid value type: {:?}", value),
    }
}
