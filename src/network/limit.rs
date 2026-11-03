//! A per-device sliding-window rate limit.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How many share listings one device may ask for per minute.
pub const LIST_PER_MINUTE: usize = 30;

/// Allows each key at most `max` events in any `window`.
#[derive(Debug)]
pub struct RateLimit {
    max: usize,
    window: Duration,
    seen: Mutex<HashMap<String, VecDeque<Instant>>>,
}

impl RateLimit {
    pub fn new(max: usize, window: Duration) -> Self {
        Self {
            max,
            window,
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// The limit for share listings.
    pub fn listings() -> Self {
        Self::new(LIST_PER_MINUTE, Duration::from_secs(60))
    }

    /// Record an event for `key` now, unless that would go over the limit.
    pub fn allow(&self, key: &str) -> bool {
        self.allow_at(key, Instant::now())
    }

    fn allow_at(&self, key: &str, now: Instant) -> bool {
        let mut seen = self.seen.lock().unwrap();
        // Forget devices that have been quiet for a whole window.
        seen.retain(|_, times| {
            times
                .back()
                .is_some_and(|t| now.duration_since(*t) < self.window)
        });
        let times = seen.entry(key.to_owned()).or_default();
        while times
            .front()
            .is_some_and(|t| now.duration_since(*t) >= self.window)
        {
            times.pop_front();
        }
        if times.len() >= self.max {
            return false;
        }
        times.push_back(now);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_limit_per_window_and_per_device() {
        let limit = RateLimit::new(3, Duration::from_secs(60));
        let start = Instant::now();
        for i in 0..3 {
            assert!(limit.allow_at("a", start + Duration::from_secs(i)));
        }
        assert!(!limit.allow_at("a", start + Duration::from_secs(10)));
        // Another device has its own budget.
        assert!(limit.allow_at("b", start + Duration::from_secs(10)));
        // Refused attempts don't count; the first slot frees at 60 s.
        assert!(!limit.allow_at("a", start + Duration::from_secs(59)));
        assert!(limit.allow_at("a", start + Duration::from_secs(60)));
        assert!(!limit.allow_at("a", start + Duration::from_secs(60)));
    }
}
