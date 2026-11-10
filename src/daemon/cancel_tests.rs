//! Issue #33: either side can cancel a transfer midway; both report it and
//! nothing is left behind.

use super::tests::{daemon, loopback};
use super::*;
use std::time::{Duration, Instant};

const GIB: u64 = 1 << 30;

/// Wait (up to 60 s) until transfer `id` has moved at least `bytes`.
async fn reached(table: &TransferTable, id: &str, bytes: u64) -> Transfer {
    for _ in 0..6000 {
        if let Some(t) = table.get(id) {
            assert!(
                !t.status.is_final(),
                "ended before it could be cancelled: {t:?}"
            );
            if t.bytes >= bytes {
                return t;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "transfer {id} never reached {bytes} bytes: {:?}",
        table.get(id)
    );
}

/// The incoming row on `daemon` that's still running.
async fn incoming(daemon: &Daemon) -> String {
    for _ in 0..500 {
        if let Some(t) = daemon
            .transfers
            .list()
            .into_iter()
            .find(|t| !t.status.is_final())
        {
            return t.transfer_id;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("nothing arrived");
}

/// Both rows `cancelled`, timed from the cancel.
async fn both_cancelled(
    started: Instant,
    sender: &Daemon,
    sent: &str,
    receiver: &Daemon,
    received: &str,
) -> (Transfer, Transfer, Duration) {
    loop {
        let out = sender.transfers.get(sent).unwrap();
        let inc = receiver.transfers.get(received).unwrap();
        if out.status.is_final() && inc.status.is_final() {
            return (out, inc, started.elapsed());
        }
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{out:?} {inc:?}"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Everything in `dir`, hidden temp files included.
fn leftovers(dir: &Path) -> Vec<String> {
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default()
}

/// Acceptance: cancel at about 50% of a 1 GB loopback transfer, first from
/// the sender, then from the receiver. Both sides report `cancelled` within
/// 1 s and no `.part` file remains.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cancelling_midway_from_either_side() {
    let src = tempfile::tempdir().unwrap();
    let a_dir = tempfile::tempdir().unwrap();
    let b_dir = tempfile::tempdir().unwrap();
    // A sparse 1 GB file: cheap to make, still 1 GB on the wire.
    let big = src.path().join("big.bin");
    std::fs::File::create(&big).unwrap().set_len(GIB).unwrap();
    let a = daemon("A", a_dir.path(), Approval::AcceptAll).await;
    let b = daemon("B", b_dir.path(), Approval::AcceptAll).await;

    for from_sender in [true, false] {
        let who = if from_sender { "sender" } else { "receiver" };
        let sent = a.send_file(&loopback(&b), &big).await.unwrap();
        let at = reached(&a.transfers, &sent, GIB / 2).await;
        let received = incoming(&b).await;
        let started = Instant::now();
        if from_sender {
            a.transfers.cancel(&sent).unwrap();
        } else {
            b.transfers.cancel(&received).unwrap();
        }
        let (out, inc, took) = both_cancelled(started, &a, &sent, &b, &received).await;
        println!(
            "cancelled by the {who} at {:.0}%: both sides final after {took:?} \
             (sender {:?} {:?}, receiver {:?} {:?})",
            at.bytes as f64 * 100.0 / GIB as f64,
            out.status,
            out.error,
            inc.status,
            inc.error,
        );
        assert_eq!(out.status, Status::Cancelled, "{who}: {out:?}");
        assert_eq!(inc.status, Status::Cancelled, "{who}: {inc:?}");
        assert!(took < Duration::from_secs(1), "{who}: took {took:?}");
        // The side that didn't press Cancel says who did.
        if from_sender {
            assert_eq!(inc.error.as_deref(), Some("the sender cancelled it"));
        } else {
            assert_eq!(out.error.as_deref(), Some("B cancelled it"));
        }
        // No .part (or anything else) on the receiving side.
        let mut left = leftovers(b_dir.path());
        for _ in 0..100 {
            if left.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            left = leftovers(b_dir.path());
        }
        assert_eq!(left, Vec::<String>::new(), "{who}: files left behind");
    }
}
