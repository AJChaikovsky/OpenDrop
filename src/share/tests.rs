use super::*;

/// A config dir, a shared folder `Reports` holding `q3.pdf` and `sub/notes.txt`,
/// and a secret file next to (outside) it.
struct Fixture {
    _tmp: tempfile::TempDir,
    config: PathBuf,
    reports: PathBuf,
    secret: PathBuf,
    downloads: PathBuf,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().canonicalize().unwrap();
    let reports = base.join("Reports");
    std::fs::create_dir_all(reports.join("sub")).unwrap();
    std::fs::write(reports.join("q3.pdf"), b"%PDF q3").unwrap();
    std::fs::write(reports.join("sub").join("notes.txt"), b"notes").unwrap();
    let secret = base.join("secret.txt");
    std::fs::write(&secret, b"do not share").unwrap();
    Fixture {
        config: base.join("config"),
        downloads: base.join("downloads"),
        reports,
        secret,
        _tmp: tmp,
    }
}

impl Fixture {
    fn shares(&self) -> Shares {
        Shares::new(&self.config, Some(&self.downloads))
    }
}

fn paths(files: &[SharedFile]) -> Vec<&str> {
    files.iter().map(|f| f.path.as_str()).collect()
}

fn rejected(shares: &Shares, id: &str) {
    match shares.resolve(id) {
        Err(ShareError::NotShared) => {}
        other => panic!("{id:?} was not rejected: {other:?}"),
    }
}

#[test]
fn nothing_is_shared_by_default() {
    let f = fixture();
    assert!(f.shares().list(None).unwrap().is_empty());
    assert!(f.shares().roots().unwrap().is_empty());
}

#[test]
fn shared_folder_lists_its_files_with_stable_ids() {
    let f = fixture();
    let shares = f.shares();
    shares.add(&f.reports).unwrap();
    let files = shares.list(None).unwrap();
    assert_eq!(paths(&files), ["Reports/q3.pdf", "Reports/sub/notes.txt"]);
    assert_eq!(files[0].name, "q3.pdf");
    assert_eq!(files[0].size, 7);
    // Same id on the next listing, and it resolves to the real file.
    assert_eq!(shares.list(None).unwrap(), files);
    let resolved = shares.resolve(&files[1].file_id).unwrap();
    assert_eq!(resolved.disk_path, f.reports.join("sub").join("notes.txt"));
    assert_eq!(
        paths(&shares.list(Some("NOTES")).unwrap()),
        ["Reports/sub/notes.txt"]
    );
    // A different device (config dir) gives the same file a different id.
    let other = Shares::new(&f.config.join("other"), None);
    other.add(&f.reports).unwrap();
    assert_ne!(other.list(None).unwrap()[0].file_id, files[0].file_id);
}

#[test]
fn a_single_file_can_be_shared() {
    let f = fixture();
    let shares = f.shares();
    shares.add(&f.reports.join("q3.pdf")).unwrap();
    assert_eq!(paths(&shares.list(None).unwrap()), ["q3.pdf"]);
}

/// Issue #19 acceptance: `../` traversal and absolute paths are rejected.
/// Requests carry ids, never paths, so anything path-shaped is refused,
/// even the absolute path of a file that is shared.
#[test]
fn paths_are_not_ids() {
    let f = fixture();
    let shares = f.shares();
    shares.add(&f.reports).unwrap();
    for attempt in [
        "../secret.txt",
        "Reports/../../secret.txt",
        "sub/../../secret.txt",
        "..",
        "Reports/q3.pdf",
        "q3.pdf",
        "",
    ] {
        rejected(&shares, attempt);
    }
    rejected(&shares, &f.secret.display().to_string());
    rejected(&shares, &f.reports.join("q3.pdf").display().to_string());
    rejected(&shares, "/etc/passwd");
    rejected(&shares, r"C:\Windows\win.ini");
    // Id-shaped, but for the file outside the root.
    rejected(&shares, &shares.file_id_for(&f.secret).unwrap());
}

/// Issue #19 acceptance: a symlink inside a root that points outside it is
/// neither listed nor fetchable; one pointing inside the root is fine.
#[cfg(unix)]
#[test]
fn symlinks_cannot_leave_a_root() {
    let f = fixture();
    let shares = f.shares();
    std::os::unix::fs::symlink(&f.secret, f.reports.join("innocent.txt")).unwrap();
    std::os::unix::fs::symlink(f.secret.parent().unwrap(), f.reports.join("up")).unwrap();
    std::os::unix::fs::symlink(f.reports.join("q3.pdf"), f.reports.join("alias.pdf")).unwrap();
    shares.add(&f.reports).unwrap();
    let files = shares.list(None).unwrap();
    // alias.pdf is the same file as q3.pdf, so it is listed once, by its
    // real name.
    assert_eq!(paths(&files), ["Reports/q3.pdf", "Reports/sub/notes.txt"]);
    assert!(
        files
            .iter()
            .all(|f| !f.path.contains("innocent") && !f.path.contains("up/"))
    );
    rejected(&shares, &shares.file_id_for(&f.secret).unwrap());
}

/// Issue #19 acceptance: hidden files (and everything in hidden folders)
/// are skipped.
#[test]
fn hidden_files_are_skipped() {
    let f = fixture();
    let shares = f.shares();
    std::fs::write(f.reports.join(".env"), b"TOKEN=1").unwrap();
    std::fs::create_dir(f.reports.join(".git")).unwrap();
    std::fs::write(f.reports.join(".git").join("config"), b"x").unwrap();
    shares.add(&f.reports).unwrap();
    assert_eq!(
        paths(&shares.list(None).unwrap()),
        ["Reports/q3.pdf", "Reports/sub/notes.txt"]
    );
    rejected(
        &shares,
        &shares.file_id_for(&f.reports.join(".env")).unwrap(),
    );
    rejected(
        &shares,
        &shares
            .file_id_for(&f.reports.join(".git").join("config"))
            .unwrap(),
    );
}

/// Issue #19 acceptance: the download folder is never shared, inside a
/// shared folder or on its own.
#[test]
fn the_download_folder_is_never_shared() {
    let f = fixture();
    let downloads = f.reports.join("OpenDrop");
    std::fs::create_dir(&downloads).unwrap();
    std::fs::write(downloads.join("received.bin"), b"from a peer").unwrap();
    let shares = Shares::new(&f.config, Some(&downloads));
    shares.add(&f.reports).unwrap();
    assert_eq!(
        paths(&shares.list(None).unwrap()),
        ["Reports/q3.pdf", "Reports/sub/notes.txt"]
    );
    let received = downloads.canonicalize().unwrap().join("received.bin");
    rejected(&shares, &shares.file_id_for(&received).unwrap());
    assert!(matches!(
        shares.add(&downloads),
        Err(ShareError::Refused(_))
    ));
    assert!(matches!(shares.add(&received), Err(ShareError::Refused(_))));
}

/// Issue #19 acceptance: an unshared id and a stale id after `share remove`
/// are rejected.
#[test]
fn unshared_and_stale_ids_are_rejected() {
    let f = fixture();
    let shares = f.shares();
    shares.add(&f.reports).unwrap();
    let id = shares.list(None).unwrap()[0].file_id.clone();
    shares.resolve(&id).unwrap();
    rejected(&shares, &format!("f_{}", "0".repeat(32)));
    rejected(&shares, &format!("f_{}", "a".repeat(31)));
    assert!(shares.remove(&f.reports).unwrap());
    assert!(!shares.remove(&f.reports).unwrap());
    rejected(&shares, &id);
    assert!(shares.list(None).unwrap().is_empty());
}

/// Issue #19 acceptance: a root with 1,000 files lists all of them with the
/// right names and sizes.
#[test]
fn lists_a_thousand_files() {
    let f = fixture();
    let big = f.reports.parent().unwrap().join("Big");
    for i in 0..1000 {
        let dir = big.join(format!("d{}", i % 10));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(format!("file-{i:04}.dat")), vec![b'x'; i]).unwrap();
    }
    let shares = f.shares();
    shares.add(&big).unwrap();
    let started = std::time::Instant::now();
    let files = shares.list(None).unwrap();
    println!("listed {} files in {:?}", files.len(), started.elapsed());
    assert_eq!(files.len(), 1000);
    for file in &files {
        let i: usize = file.name["file-".len().."file-".len() + 4].parse().unwrap();
        assert_eq!(file.name, format!("file-{i:04}.dat"));
        assert_eq!(file.path, format!("Big/d{}/{}", i % 10, file.name));
        assert_eq!(file.size, i as u64);
    }
    let mut ids: Vec<&str> = files.iter().map(|f| f.file_id.as_str()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 1000);
}

#[test]
fn damaged_file_is_an_error() {
    let f = fixture();
    std::fs::create_dir_all(&f.config).unwrap();
    std::fs::write(f.config.join(SHARES_FILE), b"{not json").unwrap();
    assert!(matches!(f.shares().list(None), Err(ShareError::Damaged(_))));
}

#[test]
fn hmac_matches_rfc_4231_style_vector() {
    // HMAC-SHA256 with key 0x0b * 32 over "Hi There" (computed with a
    // reference implementation).
    let mac = hmac_sha256(&[0x0b; 32], b"Hi There");
    assert_eq!(
        crate::transfer::hex(&mac),
        "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7"
    );
}
