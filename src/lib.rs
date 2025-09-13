//! This crate assists in managing network addresses gossiped over the Bitcoin peer-to-peer
//! network. The goals of an address book are to prevent any single peer from filling all entries
//! in the address book, resist eclipse attacks, and to help find useful peers quickly.

use std::{
    hash::{DefaultHasher, Hash, Hasher},
    net::IpAddr,
    time::{Duration, SystemTime},
};

use bitcoin::p2p::{address::AddrV2, ServiceFlags};

const ONE_MINUTE: Duration = Duration::from_secs(60);
const ONE_WEEK: Duration = Duration::from_secs(604800);

/// A record of a potential Bitcoin peer.
#[derive(Debug, Clone)]
pub struct Record {
    addr: AddrV2,
    port: u16,
    source: SourceId,
    services: ServiceFlags,
    failed_attempts: u8,
    last_connection: Option<SystemTime>,
    last_attempt: Option<SystemTime>,
}

impl Record {
    /// Construct a new record from a gossip message.
    pub fn new(addr: AddrV2, port: u16, services: ServiceFlags, source: &IpAddr) -> Self {
        let source = source.source_id();
        Self {
            addr,
            port,
            source,
            services,
            failed_attempts: 0,
            last_connection: None,
            last_attempt: None,
        }
    }

    fn destination_id(&self) -> DestinationId {
        self.addr.destination_id()
    }

    /// The network address and port to reach this peer.
    pub fn network_addr(&self) -> (AddrV2, u16) {
        (self.addr.clone(), self.port)
    }

    /// The services advertised by the peer.
    pub fn service_flags(&self) -> ServiceFlags {
        self.services
    }

    /// Similar to the `AddrMan::IsTerrible` function in Bitcoin Core. If the peer has been tried
    /// many times with no successes, then it is best to evict this peer from the table.
    pub fn is_terrible(&self, maximum_tries: u8, maximum_weekly_tries: u8) -> bool {
        if let Some(attempt) = self.last_attempt {
            let now = SystemTime::now();
            let since_last_attempt = now
                .duration_since(attempt)
                .expect("system clock moving backwards");
            if since_last_attempt < ONE_MINUTE {
                return false;
            }
            if self.failed_attempts > maximum_weekly_tries && since_last_attempt < ONE_WEEK {
                return true;
            }
        }
        if self.failed_attempts > maximum_tries {
            return true;
        }
        false
    }
}

/// A table of records to store potential peers. Some properties of this table are: a single source
/// of gossip cannot fill this entire table with addresses, the table is a fixed size and held
/// entirely in memory, the table is represented as a 2D matrix.
///
/// `B` represents the bumber of "buckets" that hold addresses. A source may only add addresses to
/// a subset of the buckets.
///
/// `S` represents the number of "slots" per bucket. A slot is either occupied with an entry or free.
///
/// `W` is the maximum amount of buckets a source is allowed to add to, where `W < B`
///
/// A table is simply a `B x S` matrix to store peers. Limiting the buckets `B` a source may add
/// peers to creates an eclipse-resistance in the contect of Bitcoin. Otherwise, this is an
/// un-ordered list.
#[derive(Debug)]
pub struct Table<const B: usize, const S: usize, const W: usize> {
    buckets: [Bucket<S>; B],
}

impl<const B: usize, const S: usize, const W: usize> Table<B, S, W> {
    // Used to compute a random bucket range for a `source_id`
    const RUN: usize = B / W;

    // Derive the bucket to store a record. Crucially, a single source ID cannot fill the entire
    // range of buckets.
    //
    // For example, let B = 1024, S = 64, W = 64, then RUN = 16.
    // Say the `source_id` modulo W is 63, and the `destination_id` modulo W is 7.
    //
    // We derive a bucket (63 * 16) + 7 % 1024 = 1015
    fn derive_bucket(record: &Record) -> usize {
        let salt = usize::from_le_bytes(record.source.0) % W;
        let range = (salt * Self::RUN) % B;
        let index = usize::from_le_bytes(record.destination_id().0) % W;
        (range + index) % B
    }

    // Select a random bucket psuedo-randomly.
    fn random_bucket() -> usize {
        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        usize::from_le_bytes(hasher.finish().to_le_bytes()) % B
    }

    fn random_slot() -> usize {
        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        usize::from_le_bytes(hasher.finish().to_le_bytes()) % S
    }

    fn random_from_bucket(bucket: &Bucket<S>) -> Option<Record> {
        if bucket.is_empty() {
            return None;
        }
        let slot_index = Self::random_slot();
        let mut tmp = (slot_index + 1) % S;
        while tmp.ne(&slot_index) {
            let record = bucket.get(tmp);
            if let Some(record) = record {
                let Some(last_attempt) = record.last_attempt else {
                    return Some(record);
                };
                let now = SystemTime::now();
                if now
                    .duration_since(last_attempt)
                    .expect("system clock moving backwards")
                    > ONE_MINUTE
                {
                    return Some(record);
                }
            }
            tmp = (tmp + 1) % S;
        }
        bucket.get(slot_index)
    }

    /// Build a new table to store records of peers.
    pub fn new() -> Self {
        let buckets: [Bucket<S>; B] = [const { Bucket::new() }; B];
        Self { buckets }
    }

    /// Add a peer to this table. If there is a conflict at the designated slot, then the
    /// conflicting record is returned.
    ///
    /// Note that bucket and slot indices are computed deterministically, so conflicts must be
    /// resolved.
    pub fn add(&mut self, record: &Record) -> Option<Record> {
        let bucket_index = Self::derive_bucket(record);
        self.buckets[bucket_index].add(record.clone())
    }

    /// Remove a record from it's slot.
    pub fn remove(&mut self, record: &Record) {
        let bucket_index = Self::derive_bucket(record);
        self.buckets[bucket_index].remove(record);
    }

    /// Is the entire address book empty.
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|bucket| bucket.is_empty())
    }

    /// Select an address randomly from the address book.
    ///
    /// First, a random bucket will be selected to poll a peer from. If the bucket is non-empty,
    /// a random peer will be returned from the bucket. Otherwise, the buckets will be iterated
    /// over until a peer is found. If no peers are found after the exhaustive search, `None` is
    /// returned.
    pub fn select(&self) -> Option<Record> {
        if self.is_empty() {
            return None;
        };
        let bucket_index = Self::random_bucket();
        let bucket = &self.buckets[bucket_index];
        if bucket.is_empty() {
            let mut tmp = (bucket_index + 1) % B;
            while tmp.ne(&bucket_index) {
                let bucket = &self.buckets[tmp];
                let random_record = Self::random_from_bucket(bucket);
                if random_record.is_some() {
                    return random_record;
                }
                tmp = (tmp + 1) % B;
            }
            None
        } else {
            Self::random_from_bucket(bucket)
        }
    }

    /// Report a successful connection to `Record`
    pub fn successful_connection(&mut self, record: &Record) {
        let bucket_index = Self::derive_bucket(record);
        let bucket = &mut self.buckets[bucket_index];
        bucket.successful_connection(record);
    }

    /// Report a failed connection to `Record`
    pub fn failed_connection(&mut self, record: &Record) {
        let bucket_index = Self::derive_bucket(record);
        let bucket = &mut self.buckets[bucket_index];
        bucket.failed_connection(record);
    }
}

impl<const B: usize, const S: usize, const W: usize> Default for Table<B, S, W> {
    fn default() -> Self {
        Table::<B, S, W>::new()
    }
}

#[derive(Debug)]
struct Bucket<const S: usize> {
    records: [Option<Record>; S],
}

impl<const S: usize> Bucket<S> {
    fn derive_slot(record: &Record) -> usize {
        let index = usize::from_le_bytes(record.destination_id().0);
        index % S
    }

    const fn new() -> Self {
        let records: [Option<Record>; S] = [const { None }; S];
        Self { records }
    }

    fn add(&mut self, record: Record) -> Option<Record> {
        let slot = Self::derive_slot(&record);
        match &self.records[slot] {
            Some(occupied) => Some(occupied.clone()),
            None => {
                self.records[slot] = Some(record);
                None
            }
        }
    }

    fn remove(&mut self, record: &Record) {
        let slot = Self::derive_slot(record);
        self.records[slot] = None;
    }

    fn is_empty(&self) -> bool {
        self.records.iter().all(|record| record.is_none())
    }

    fn successful_connection(&mut self, record: &Record) {
        let slot = Self::derive_slot(record);
        if let Some(record) = &mut self.records[slot] {
            record.last_attempt = Some(SystemTime::now());
            record.last_connection = Some(SystemTime::now());
            record.failed_attempts = 0;
        }
    }

    fn failed_connection(&mut self, record: &Record) {
        let slot = Self::derive_slot(record);
        if let Some(record) = &mut self.records[slot] {
            record.last_attempt = Some(SystemTime::now());
            record.failed_attempts += 1;
        }
    }

    fn get(&self, index: usize) -> Option<Record> {
        let index = index % S;
        self.records[index].clone()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
struct SourceId([u8; 8]);

trait SourceIdExt {
    fn source_id(&self) -> SourceId;
}

impl SourceIdExt for IpAddr {
    fn source_id(&self) -> SourceId {
        let mut hasher = DefaultHasher::new();
        match self {
            Self::V4(ipv4) => {
                let octets = ipv4.octets();
                let first_two_octets = [octets[0], octets[1]];
                first_two_octets.hash(&mut hasher);
                let hash = hasher.finish();
                let bytes = hash.to_le_bytes();
                SourceId(bytes)
            }
            Self::V6(ipv6) => {
                let octets = ipv6.octets();
                let first_four_octets = [octets[0], octets[1], octets[2], octets[3]];
                first_four_octets.hash(&mut hasher);
                let hash = hasher.finish();
                let bytes = hash.to_le_bytes();
                SourceId(bytes)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, std::hash::Hash)]
struct DestinationId([u8; 8]);

trait DestinationIdExt {
    fn destination_id(&self) -> DestinationId;
}

impl DestinationIdExt for AddrV2 {
    fn destination_id(&self) -> DestinationId {
        let mut hasher = DefaultHasher::new();
        match self {
            Self::Ipv4(ipv4) => {
                ipv4.octets().hash(&mut hasher);
                DestinationId(hasher.finish().to_le_bytes())
            }
            Self::Ipv6(ipv6) => {
                ipv6.octets().hash(&mut hasher);
                DestinationId(hasher.finish().to_le_bytes())
            }
            Self::I2p(i2p) => {
                i2p.hash(&mut hasher);
                DestinationId(hasher.finish().to_le_bytes())
            }
            Self::TorV3(tv3) => {
                tv3.hash(&mut hasher);
                DestinationId(hasher.finish().to_le_bytes())
            }
            Self::Cjdns(ipv6) => {
                ipv6.octets().hash(&mut hasher);
                DestinationId(hasher.finish().to_le_bytes())
            }
            _ => {
                "unknown network address".hash(&mut hasher);
                DestinationId(hasher.finish().to_le_bytes())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use bitcoin::p2p::{address::AddrV2, ServiceFlags};

    use crate::{Record, Table};

    const LOCAL_HOST: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
    const DUMB: AddrV2 = AddrV2::Ipv4(LOCAL_HOST);

    const BUCKETS: usize = 256;
    const SLOTS: usize = 16;
    const RANGE: usize = 16;

    #[test]
    fn test_simple_table_situations() {
        let mut table = Table::<BUCKETS, SLOTS, RANGE>::new();
        assert!(table.is_empty());
        assert!(table.select().is_none());
        let record = Record::new(DUMB, 8333, ServiceFlags::NONE, &IpAddr::V4(LOCAL_HOST));
        table.add(&record);
        assert!(!table.is_empty());
        // We should always be able to find this peer in exhaustive search.
        for _ in 0..BUCKETS * SLOTS {
            assert!(table.select().is_some());
        }
        // Adding the same record should always conflict.
        for _ in 0..BUCKETS * SLOTS {
            assert!(table.add(&record).is_some());
        }
    }
}
