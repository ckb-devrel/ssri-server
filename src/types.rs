use core::marker::PhantomData;
use std::fmt::Debug;

use ckb_jsonrpc_types::CellOutput;
use ckb_vm::Bytes;
use core::fmt;
use hex::{FromHex, ToHex};
use serde::{
    de::{Error, Visitor},
    Deserialize, Deserializer, Serialize, Serializer,
};

pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: ToHex,
{
    let s = format!("0x{}", data.encode_hex::<String>());
    serializer.serialize_str(&s)
}

pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromHex,
    <T as FromHex>::Error: fmt::Display,
{
    struct HexStrVisitor<T>(PhantomData<T>);

    impl<'de, T> Visitor<'de> for HexStrVisitor<T>
    where
        T: FromHex,
        <T as FromHex>::Error: fmt::Display,
    {
        type Value = T;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a 0x-prefixed hex encoded string")
        }

        fn visit_str<E>(self, data: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            if !data.starts_with("0x") {
                Err(Error::custom("expected a 0x-prefixed hex encoded string"))
            } else {
                FromHex::from_hex(&data[2..]).map_err(Error::custom)
            }
        }

        fn visit_borrowed_str<E>(self, data: &'de str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            if !data.starts_with("0x") {
                Err(Error::custom("expected a 0x-prefixed hex encoded string"))
            } else {
                FromHex::from_hex(&data[2..]).map_err(Error::custom)
            }
        }
    }

    deserializer.deserialize_str(HexStrVisitor(PhantomData))
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
pub struct Hex {
    #[serde(serialize_with = "serialize", deserialize_with = "deserialize")]
    pub hex: Vec<u8>,
}

impl Debug for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", self.hex.encode_hex::<String>())
    }
}

impl From<Bytes> for Hex {
    fn from(value: Bytes) -> Self {
        Self {
            hex: value.to_vec(),
        }
    }
}

impl From<&str> for Hex {
    fn from(value: &str) -> Self {
        if !value.starts_with("0x") {
            panic!("expected a 0x-prefixed hex encoded string");
        }
        let hex_str = &value[2..];
        let hex_bytes = Vec::from_hex(hex_str).unwrap();
        Self { hex: hex_bytes }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CellOutputWithData {
    pub cell_output: CellOutput,
    pub hex_data: Option<Hex>,
}
