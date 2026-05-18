//! In-process key-value store — no external deps, used in dev/test when Redis
//! is not configured.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

struct Entry {
    value: Vec<u8>,
    expires: Option<Instant>,
}

impl Entry {
    fn is_expired(&self) -> bool {
        self.expires.map_or(false, |exp| Instant::now() > exp)
    }
}

pub struct MemoryStore {
    data: RwLock<HashMap<String, Entry>>,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        let map = self.data.read().await;
        match map.get(key) {
            Some(e) if !e.is_expired() => Some(e.value.clone()),
            _ => None,
        }
    }

    pub async fn set(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) {
        let expires = ttl.map(|d| Instant::now() + d);
        self.data.write().await.insert(
            key.to_string(),
            Entry { value, expires },
        );
    }

    pub async fn del(&self, key: &str) {
        self.data.write().await.remove(key);
    }

    /// Atomically increment an integer counter stored as a decimal string.
    /// Returns the new value.
    pub async fn incr(&self, key: &str) -> i64 {
        let mut map = self.data.write().await;
        let entry = map.entry(key.to_string()).or_insert_with(|| Entry {
            value: b"0".to_vec(),
            expires: None,
        });
        let n: i64 = std::str::from_utf8(&entry.value)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
            + 1;
        entry.value = n.to_string().into_bytes();
        n
    }

    /// Evict all expired entries.
    pub async fn gc(&self) {
        self.data.write().await.retain(|_, e| !e.is_expired());
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn get_set_del() {
        let store = MemoryStore::new();
        assert!(store.get("k").await.is_none());

        store.set("k", b"hello".to_vec(), None).await;
        assert_eq!(store.get("k").await.unwrap(), b"hello");

        store.del("k").await;
        assert!(store.get("k").await.is_none());
    }

    #[tokio::test]
    async fn ttl_expiry() {
        let store = MemoryStore::new();
        store
            .set("k", b"v".to_vec(), Some(Duration::from_millis(1)))
            .await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        assert!(store.get("k").await.is_none(), "should have expired");
    }

    #[tokio::test]
    async fn incr_counter() {
        let store = MemoryStore::new();
        assert_eq!(store.incr("c").await, 1);
        assert_eq!(store.incr("c").await, 2);
        assert_eq!(store.incr("c").await, 3);
        assert_eq!(store.incr("other").await, 1);
    }

    #[tokio::test]
    async fn gc_removes_expired() {
        let store = MemoryStore::new();
        store.set("a", b"1".to_vec(), Some(Duration::from_millis(1))).await;
        store.set("b", b"2".to_vec(), None).await;
        tokio::time::sleep(Duration::from_millis(5)).await;
        store.gc().await;
        assert!(store.get("a").await.is_none());
        assert!(store.get("b").await.is_some());
    }
}
