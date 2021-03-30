use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::io::Cursor;

pub fn check_serialization<
    T: CanonicalSerialize + CanonicalDeserialize + std::fmt::Debug + PartialEq,
>(
    obj: T,
) {
    let mut obj_bytes = vec![];
    obj.serialize(&mut obj_bytes).unwrap();
    let deserialized_obj = T::deserialize(&mut Cursor::new(obj_bytes)).unwrap();
    assert_eq!(obj, deserialized_obj);
}
