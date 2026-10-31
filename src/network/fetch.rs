//! The requester's side of fetches it started: which `fetch_offer`s it may
//! take without asking its user.

use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::oneshot;

/// What a fetch we started expects to come back.
#[derive(Debug)]
struct Expected {
    device_id: String,
    size: u64,
    /// Told the transfer id of the offer once it arrives.
    arrived: oneshot::Sender<String>,
}

/// Fetches this device started and is waiting to receive.
#[derive(Debug, Default)]
pub struct PendingFetches {
    expected: Mutex<HashMap<String, Expected>>,
    /// Transfer id of each claimed offer, to the fetch it answered.
    claimed: Mutex<HashMap<String, String>>,
}

impl PendingFetches {
    pub fn new() -> Self {
        Self::default()
    }

    /// Expect a `fetch_offer` for `fetch_id` from `device_id` of `size`
    /// bytes. The receiver gets the offer's transfer id when it arrives.
    pub fn expect(&self, fetch_id: &str, device_id: &str, size: u64) -> oneshot::Receiver<String> {
        let (arrived, rx) = oneshot::channel();
        self.expected.lock().unwrap().insert(
            fetch_id.to_owned(),
            Expected {
                device_id: device_id.to_owned(),
                size,
                arrived,
            },
        );
        rx
    }

    /// Stop expecting `fetch_id` (declined, timed out or cancelled).
    pub fn forget(&self, fetch_id: &str) {
        self.expected.lock().unwrap().remove(fetch_id);
    }

    /// An offer arrived: if `fetch_id`, the sending device and the size all
    /// match a fetch we started, use up that fetch, report `transfer_id` to
    /// whoever started it, and return true. Otherwise nothing changes and
    /// the offer must be treated like any other.
    pub fn claim(&self, fetch_id: &str, device_id: &str, size: u64, transfer_id: &str) -> bool {
        let mut expected = self.expected.lock().unwrap();
        let matches = expected
            .get(fetch_id)
            .is_some_and(|e| e.device_id == device_id && e.size == size);
        if !matches {
            return false;
        }
        let entry = expected.remove(fetch_id).expect("just checked");
        // Recorded before anything is received, so progress for this
        // transfer can be matched to the fetch from the first byte.
        self.claimed
            .lock()
            .unwrap()
            .insert(transfer_id.to_owned(), fetch_id.to_owned());
        let _ = entry.arrived.send(transfer_id.to_owned());
        true
    }

    /// The fetch an incoming transfer answers, if it was a claimed offer.
    pub fn fetch_for(&self, transfer_id: &str) -> Option<String> {
        self.claimed.lock().unwrap().get(transfer_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_exact_match_is_claimed_and_only_once() {
        let pending = PendingFetches::new();
        let mut arrived = pending.expect("f1", "mac", 100);
        assert!(!pending.claim("f1", "impostor", 100, "t1"));
        assert!(!pending.claim("f1", "mac", 101, "t1"));
        assert!(!pending.claim("f2", "mac", 100, "t1"));
        assert!(arrived.try_recv().is_err());
        assert!(pending.claim("f1", "mac", 100, "t1"));
        assert_eq!(arrived.try_recv().unwrap(), "t1");
        assert_eq!(pending.fetch_for("t1").as_deref(), Some("f1"));
        assert_eq!(pending.fetch_for("t9"), None);
        assert!(!pending.claim("f1", "mac", 100, "t2"));
        let _later = pending.expect("f3", "mac", 1);
        pending.forget("f3");
        assert!(!pending.claim("f3", "mac", 1, "t3"));
    }
}
