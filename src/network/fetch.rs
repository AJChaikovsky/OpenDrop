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
    /// Cancelled after the owner said yes: refuse the offer when it comes.
    cancelled: bool,
}

/// An offer we took for one of our fetches.
#[derive(Debug)]
struct Claimed {
    fetch_id: String,
    /// Stops the receive, if it is still running.
    stop: Option<oneshot::Sender<()>>,
}

/// What to do with an incoming `fetch_offer`.
#[derive(Debug)]
pub enum Claim {
    /// It answers a fetch we started: take it without asking, and stop
    /// receiving if this fires.
    Ours(oneshot::Receiver<()>),
    /// It answers a fetch we cancelled: refuse it.
    Cancelled,
    /// Not ours: treat it like any other offer.
    NotOurs,
}

/// Fetches this device started and is waiting to receive.
#[derive(Debug, Default)]
pub struct PendingFetches {
    expected: Mutex<HashMap<String, Expected>>,
    /// Transfer id of each claimed offer, to the fetch it answered.
    claimed: Mutex<HashMap<String, Claimed>>,
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
                cancelled: false,
            },
        );
        rx
    }

    /// Stop expecting `fetch_id` (declined, timed out or cancelled).
    pub fn forget(&self, fetch_id: &str) {
        self.expected.lock().unwrap().remove(fetch_id);
    }

    /// Stop `fetch_id` after the owner approved it: refuse its offer if it
    /// hasn't arrived yet, or stop receiving it if it has. Returns false if
    /// there is nothing to stop.
    pub fn cancel(&self, fetch_id: &str) -> bool {
        if let Some(entry) = self.expected.lock().unwrap().get_mut(fetch_id) {
            entry.cancelled = true;
            return true;
        }
        let mut claimed = self.claimed.lock().unwrap();
        let stop = claimed
            .values_mut()
            .find(|c| c.fetch_id == fetch_id)
            .and_then(|c| c.stop.take());
        stop.is_some_and(|stop| stop.send(()).is_ok())
    }

    /// An offer arrived: if `fetch_id`, the sending device and the size all
    /// match a fetch we started, use up that fetch and report `transfer_id`
    /// to whoever started it. Otherwise nothing changes and the offer must
    /// be treated like any other.
    pub fn claim(&self, fetch_id: &str, device_id: &str, size: u64, transfer_id: &str) -> Claim {
        let mut expected = self.expected.lock().unwrap();
        let matches = expected
            .get(fetch_id)
            .is_some_and(|e| e.device_id == device_id && e.size == size);
        if !matches {
            return Claim::NotOurs;
        }
        let entry = expected.remove(fetch_id).expect("just checked");
        if entry.cancelled {
            return Claim::Cancelled;
        }
        // Recorded before anything is received, so progress for this
        // transfer can be matched to the fetch from the first byte.
        let (stop, stopped) = oneshot::channel();
        self.claimed.lock().unwrap().insert(
            transfer_id.to_owned(),
            Claimed {
                fetch_id: fetch_id.to_owned(),
                stop: Some(stop),
            },
        );
        let _ = entry.arrived.send(transfer_id.to_owned());
        Claim::Ours(stopped)
    }

    /// The fetch an incoming transfer answers, if it was a claimed offer.
    pub fn fetch_for(&self, transfer_id: &str) -> Option<String> {
        self.claimed
            .lock()
            .unwrap()
            .get(transfer_id)
            .map(|c| c.fetch_id.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_an_exact_match_is_claimed_and_only_once() {
        let pending = PendingFetches::new();
        let mut arrived = pending.expect("f1", "mac", 100);
        let ours = |c: Claim| matches!(c, Claim::Ours(_));
        assert!(!ours(pending.claim("f1", "impostor", 100, "t1")));
        assert!(!ours(pending.claim("f1", "mac", 101, "t1")));
        assert!(!ours(pending.claim("f2", "mac", 100, "t1")));
        assert!(arrived.try_recv().is_err());
        let Claim::Ours(mut stopped) = pending.claim("f1", "mac", 100, "t1") else {
            panic!("f1 should be ours");
        };
        assert_eq!(arrived.try_recv().unwrap(), "t1");
        assert_eq!(pending.fetch_for("t1").as_deref(), Some("f1"));
        assert_eq!(pending.fetch_for("t9"), None);
        assert!(!ours(pending.claim("f1", "mac", 100, "t2")));
        let _later = pending.expect("f3", "mac", 1);
        pending.forget("f3");
        assert!(!ours(pending.claim("f3", "mac", 1, "t3")));

        // Cancelling a claimed fetch stops its receive, once.
        assert!(stopped.try_recv().is_err());
        assert!(pending.cancel("f1"));
        assert!(stopped.try_recv().is_ok());
        assert!(!pending.cancel("f1"));
    }

    #[test]
    fn an_offer_for_a_cancelled_fetch_is_refused() {
        let pending = PendingFetches::new();
        let _arrived = pending.expect("f1", "mac", 100);
        assert!(pending.cancel("f1"));
        assert!(matches!(
            pending.claim("f1", "mac", 100, "t1"),
            Claim::Cancelled
        ));
        assert!(matches!(
            pending.claim("f1", "mac", 100, "t1"),
            Claim::NotOurs
        ));
        assert!(!pending.cancel("nope"));
    }
}
