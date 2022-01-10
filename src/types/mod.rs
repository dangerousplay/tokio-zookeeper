//
// Copyright 2020 Joyent, Inc.
//

pub mod acl;
pub use self::acl::*;

pub mod watch;
pub use self::watch::*;

pub mod multi;
pub use self::multi::*;

use std::net::{AddrParseError, SocketAddr, ToSocketAddrs};
use std::str::FromStr;

use itertools::Itertools;
use serde::Deserialize;

const ADDRESS_SEPARATOR: &str = ",";
const ADDRESS_BASE_PATH_SEPARATOR: &str = "/";


///
/// Statistics about a znode, similar to the UNIX `stat` structure.
///
/// # Time in ZooKeeper
/// ZooKeeper keeps track of time in a number of ways.
///
/// - **zxid**: Every change to a ZooKeeper cluster receives a stamp in the form of a *zxid*
///   (ZooKeeper Transaction ID). This exposes the total ordering of all changes to ZooKeeper. Each
///   change will have a unique *zxid* -- if *zxid:a* is smaller than *zxid:b*, then the associated
///   change to *zxid:a* happened before *zxid:b*.
/// - **Version Numbers**: Every change to a znode will cause an increase to one of the version
///   numbers of that node.
/// - **Clock Time**: ZooKeeper does not use clock time to make decisions, but it uses it to put
///   timestamps into the `Stat` structure.
///
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Stat {
    /// The transaction ID that created the znode.
    pub czxid: i64,

    /// The last transaction that modified the znode.
    pub mzxid: i64,

    /// Milliseconds since epoch when the znode was created.
    pub ctime: i64,

    /// Milliseconds since epoch when the znode was last modified.
    pub mtime: i64,

    /// The number of changes to the data of the znode.
    pub version: i32,

    /// The number of changes to the children of the znode.
    pub cversion: i32,

    /// The number of changes to the ACL of the znode.
    pub aversion: i32,

    /// The session ID of the owner of this znode, if it is an ephemeral entry.
    pub ephemeral_owner: i64,

    /// The length of the data field of the znode.
    pub data_length: i32,

    /// The number of children this znode has.
    pub num_children: i32,

    /// The transaction ID that last modified the children of the znode.
    pub pzxid: i64,
}

///
/// CreateMode determines how the znode is created on the ZooKeeper server.
///
#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum CreateMode {
    /// The znode will not be automatically deleted upon client's disconnect.
    Persistent = 0,

    /// The znode will be deleted upon the client's disconnect.
    Ephemeral = 1,

    ///
    /// The name of the znode will be appended with a monotonically increasing number. The actual
    /// path name of a sequential node will be the given path plus a suffix `"i"` where *i* is the
    /// current sequential number of the node. The sequence number is always fixed length of 10
    /// digits, 0 padded. Once such a node is created, the sequential number will be incremented by
    /// one.
    ///
    PersistentSequential = 2,

    ///
    /// The znode will be deleted upon the client's disconnect, and its name will be appended with a
    /// monotonically increasing number.
    ///
    EphemeralSequential = 3,

    ///
    /// Container nodes are special purpose nodes useful for recipes such as leader, lock, etc. When
    /// the last child of a container is deleted, the container becomes a candidate to be deleted by
    /// the server at some point in the future. Given this property, you should be prepared to get
    /// `ZkError::NoNode` when creating children inside of this container node.
    ///
    Container = 4,
    //
    // 421
    // 000
    // ^----- is it a container?
    //  ^---- is it sequential?
    //   ^--- is it ephemeral?
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ZkConnectStringError {
    /// The connect string has no addresses
    EmptyString,

    /// An address in the connect string is malformed
    MalformedAddr
}

impl From<AddrParseError> for ZkConnectStringError {
    fn from(_: AddrParseError) -> Self {
        ZkConnectStringError::MalformedAddr
    }
}

///
/// `ZkConnectString` represents a list of zookeeper addresses to connect to.
///
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ZkConnectString(Vec<String>, Option<String>);

impl ZkConnectString {
    //
    // Get a connection String resolving to a Socket Address. Returns None
    // if the index is out of bounds or the given host has no DNS records.
    //
    pub(crate) fn get_addr_at(&self, index: usize) -> Option<SocketAddr> {
        self.0.get(index)
            .and_then(|h| h.to_socket_addrs().ok())
            .and_then(|mut a| a.next())
    }

    pub(crate) fn base_path(&self) -> Option<&String> {
        self.1.as_ref()
    }

    //
    // Returns the number of addresses in the ZkConnectString
    //
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

impl ToString for ZkConnectString {
    fn to_string(&self) -> String {
        self.0
            .iter()
            .map(|x| x.to_string())
            .intersperse(String::from(","))
            .collect()
    }
}

impl FromStr for ZkConnectString {
    type Err = ZkConnectStringError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ZkConnectStringError::EmptyString);
        }

        let acc: Result<Vec<String>, Self::Err> = Ok(vec![]);

        let base_path: Vec<&str> = s.split(ADDRESS_BASE_PATH_SEPARATOR).collect();

        let addrs = base_path.first().copied().unwrap_or(s);

        let base_path: Vec<String> = base_path.iter().skip(1)
            .map(|s| s.to_string())
            .collect();

        let base_path = if base_path.is_empty() {
            None
        } else {
            Some(base_path.join(ADDRESS_BASE_PATH_SEPARATOR))
        };

        addrs.split(ADDRESS_SEPARATOR)
            .map(|x| x.to_owned())
            .fold(acc, |acc, x| match (acc, x) {
                (Ok(mut addrs), addr) => {
                    addrs.push(addr);
                    Ok(addrs)
                }
                (Err(e), _) => Err(e),
            }).map(|addrs| ZkConnectString(addrs, base_path))
    }
}

#[cfg(test)]
mod tests {
    use crate::types::ZkConnectStringError;
    use crate::ZkConnectString;

    #[test]
    fn parse_address_base_path() {
        let addresses = vec![
            "127.0.0.1",
            "128.0.0.1",
            "129.0.0.1",
        ];

        let address = addresses.join(",");

        let base_path = "broker/path";
        let address_with_base = format!("{}/{}", address, base_path);

        let result: Result<ZkConnectString, ZkConnectStringError> = address_with_base.parse();

        assert!(result.is_ok(), "Should parse zookeeper string");

        let actual = result.unwrap();

        let actual_base_path = actual.1.expect("Base path exists");

        assert_eq!(actual_base_path, base_path);

        assert_eq!(actual.0, addresses);
    }

    #[test]
    fn parse_address() {
        let address = "127.0.0.1";

        let result: Result<ZkConnectString, ZkConnectStringError> = address.parse();

        assert!(result.is_ok(), "Should parse zookeeper string");

        let actual = result.unwrap();

        assert_eq!(actual.1, None);

        assert_eq!(actual.0, vec![address]);
    }

}
