use super::*;
use crate::daemon::{Direction, Options, Status};
use crate::network::DeviceIdentity;
use crate::network::server::Approval;
use std::time::Instant;

async fn daemon(config: &Path) -> Arc<Daemon> {
    Daemon::start(Options {
        port: 0,
        discover: false,
        control: Some(config.to_owned()),
        ..Options::new(
            DeviceIdentity::new("Desk"),
            config.join("downloads"),
            Approval::AcceptAll,
        )
    })
    .await
    .unwrap()
}

/// Connect, retrying for a moment while the daemon's endpoint comes up.
async fn client(endpoint: &Endpoint) -> Client {
    for _ in 0..100 {
        if let Ok(client) = Client::connect_to(endpoint).await {
            return client;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Client::connect_to(endpoint).await.unwrap()
}

/// Issue #18 acceptance: `list_devices` and `list_transfers` answer in
/// under 100 ms.
#[tokio::test]
async fn answers_list_requests_within_100ms() {
    let config = tempfile::tempdir().unwrap();
    let daemon = daemon(config.path()).await;
    let (id, _cancel) = daemon.transfers.begin(Transfer::new(
        Direction::Receive,
        None,
        "Mac".into(),
        "q3.pdf".into(),
        42,
    ));
    daemon
        .paired
        .insert(crate::pairing::store::PairedDevice::new(
            "dev-1".into(),
            "Laptop".into(),
            [1; 32],
        ))
        .unwrap();
    let mut client = client(&Endpoint::for_config_dir(config.path())).await;

    let mut slowest = Duration::ZERO;
    for _ in 0..20 {
        let started = Instant::now();
        let devices = client.call(&Request::ListDevices).await.unwrap();
        let transfers = client.call(&Request::ListTransfers).await.unwrap();
        slowest = slowest.max(started.elapsed() / 2);
        let Response::Devices { devices } = devices else {
            panic!("{devices:?}");
        };
        assert_eq!(devices.len(), 1);
        assert_eq!(
            (devices[0].name.as_str(), devices[0].online),
            ("Laptop", false)
        );
        let Response::Transfers { transfers } = transfers else {
            panic!("{transfers:?}");
        };
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].transfer_id, id);
    }
    println!("slowest control call of 40: {slowest:?}");
    assert!(slowest < Duration::from_millis(100), "{slowest:?}");

    // A fresh connection per call is fast too (what the CLI does).
    let started = Instant::now();
    let mut fresh = Client::connect(config.path()).await.unwrap();
    fresh.call(&Request::ListDevices).await.unwrap();
    let elapsed = started.elapsed();
    println!("connect + list_devices: {elapsed:?}");
    assert!(elapsed < Duration::from_millis(100), "{elapsed:?}");
}

#[tokio::test]
async fn gets_and_cancels_transfers() {
    let config = tempfile::tempdir().unwrap();
    let daemon = daemon(config.path()).await;
    let (id, cancelled) = daemon.transfers.begin(Transfer::new(
        Direction::Send,
        None,
        "Mac".into(),
        "a.txt".into(),
        1,
    ));
    let mut client = client(&Endpoint::for_config_dir(config.path())).await;
    let Response::Transfer { transfer } = client
        .call(&Request::GetTransfer {
            transfer_id: id.clone(),
        })
        .await
        .unwrap()
    else {
        panic!("expected a transfer");
    };
    assert_eq!(transfer.status, Status::AwaitingApproval);
    assert_eq!(
        client
            .call(&Request::CancelTransfer {
                transfer_id: id.clone()
            })
            .await
            .unwrap(),
        Response::CancelRequested {
            transfer_id: id.clone()
        }
    );
    cancelled.await.unwrap();
    assert!(matches!(
        client
            .call(&Request::GetTransfer {
                transfer_id: "nope".into()
            })
            .await
            .unwrap(),
        Response::Error { .. }
    ));
}

#[tokio::test]
async fn no_daemon_is_a_clear_error() {
    let config = tempfile::tempdir().unwrap();
    let err = Client::connect(config.path()).await.err().unwrap();
    assert!(err.to_string().contains("opendrop listen"), "{err}");
}

/// Issue #18 acceptance: a client the endpoint doesn't allow is refused.
/// Tests can't switch OS users, so the endpoint is told to allow a uid
/// other than ours; our connection must then get no answer.
#[cfg(unix)]
#[tokio::test]
async fn another_user_is_refused() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let config = tempfile::tempdir().unwrap();
    let daemon = daemon(config.path()).await;
    let mut ours = Endpoint::for_config_dir(&config.path().join("other"));
    let own_uid = std::fs::metadata(config.path()).unwrap().uid();
    ours.allowed_uid = Some(own_uid.wrapping_add(1));
    tokio::spawn(serve(Arc::clone(&daemon), ours.clone()));
    let mut client = client(&ours).await;
    // Dropped unanswered: depending on timing that reads as a hang-up or a
    // reset, never as a response.
    let refused = client.call(&Request::ListDevices).await;
    assert!(refused.is_err(), "{refused:?}");

    // And the files are locked down for everyone else.
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&ours.path), 0o600);
    assert_eq!(mode(ours.path.parent().unwrap()), 0o700);
    let default = Endpoint::for_config_dir(config.path());
    assert_eq!(mode(&default.path), 0o600);
}

/// Issue #18 acceptance on Windows: a pipe whose ACL doesn't include us
/// (SYSTEM only) can't be opened; the default ACL lets us in.
#[cfg(windows)]
#[tokio::test]
async fn another_user_is_refused() {
    let config = tempfile::tempdir().unwrap();
    let daemon = daemon(config.path()).await;
    let mut locked = Endpoint::for_config_dir(&config.path().join("other"));
    locked.sddl = Some("D:P(A;;GA;;;SY)".into());
    tokio::spawn(serve(Arc::clone(&daemon), locked.clone()));
    tokio::time::sleep(Duration::from_millis(200)).await;
    let err = platform::connect(&locked).await.unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
    let sddl = platform::own_user_sddl().unwrap();
    println!("control pipe ACL: {sddl}");
    assert!(sddl.starts_with("D:P(A;;GA;;;SY)(A;;GA;;;S-1-"), "{sddl}");
    let mut ok = client(&Endpoint::for_config_dir(config.path())).await;
    assert!(matches!(
        ok.call(&Request::ListDevices).await.unwrap(),
        Response::Devices { .. }
    ));
}
