use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::str::FromStr;

const GO_TIME_ZERO_UNIX: i64 = -62135596800;
const GO_TIME_ZERO_UNIX_MS: i64 = GO_TIME_ZERO_UNIX * 1000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GoTime {
    unix_seconds: i64,
}

impl GoTime {
    pub fn now() -> Self {
        Self {
            unix_seconds: time::OffsetDateTime::now_utc().unix_timestamp(),
        }
    }

    pub fn zero() -> Self {
        Self {
            unix_seconds: GO_TIME_ZERO_UNIX,
        }
    }

    pub fn is_zero(&self) -> bool {
        self.unix_seconds == GO_TIME_ZERO_UNIX
    }

    pub fn elapsed_seconds_since_now(&self) -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp() - self.unix_seconds
    }
}

impl Serialize for GoTime {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if self.is_zero() {
            return serializer.serialize_str("0001-01-01T00:00:00Z");
        }
        let dt = time::OffsetDateTime::from_unix_timestamp(self.unix_seconds)
            .map_err(serde::ser::Error::custom)?;
        let formatted = dt
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&formatted)
    }
}

impl<'de> Deserialize<'de> for GoTime {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s == "0001-01-01T00:00:00Z" {
            return Ok(GoTime::zero());
        }
        let dt = time::OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339)
            .map_err(serde::de::Error::custom)?;
        Ok(GoTime {
            unix_seconds: dt.unix_timestamp(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetAddress {
    pub timestamp: i64,
    pub ip: IpAddr,
    pub port: u16,
}

#[derive(Serialize, Deserialize)]
struct NetAddressJson {
    #[serde(rename = "Timestamp")]
    timestamp: serde_json::Value,
    #[serde(rename = "IP")]
    ip: String,
    #[serde(rename = "Port")]
    port: u16,
}

impl Serialize for NetAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let json = NetAddressJson {
            timestamp: serde_json::json!({}),
            ip: self.ip.to_string(),
            port: self.port,
        };
        json.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for NetAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let json = NetAddressJson::deserialize(deserializer)?;
        let ip = IpAddr::from_str(&json.ip).map_err(serde::de::Error::custom)?;
        Ok(NetAddress {
            timestamp: GO_TIME_ZERO_UNIX_MS,
            ip,
            port: json.port,
        })
    }
}

impl NetAddress {
    pub fn new(ip: IpAddr, port: u16) -> Self {
        NetAddress {
            timestamp: time::OffsetDateTime::now_utc().unix_timestamp() * 1000,
            ip,
            port,
        }
    }

    pub fn with_timestamp(ip: IpAddr, port: u16, timestamp: i64) -> Self {
        NetAddress {
            timestamp,
            ip,
            port,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SubnetworkID(pub [u8; 20]);

impl SubnetworkID {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 20 {
            return Err(format!("invalid hash size. Want: 20, got: {}", bytes.len()));
        }
        let mut data = [0u8; 20];
        data.copy_from_slice(bytes);
        Ok(SubnetworkID(data))
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, String> {
        let bytes = hex::decode(hex_str).map_err(|e| e.to_string())?;
        Self::from_bytes(&bytes)
    }
}
