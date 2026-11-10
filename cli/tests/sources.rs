//! Git sources: the store, the Zig fetch path (with a stand-in `zig` that
//! prints what Zig 0.17.1 prints and leaves its checkout where Zig does),
//! and the HTTP server buck2 downloads from. No network.

use hartland::digest::{GitSha, Sha256};
use hartland::sources::{GitUrl, Pins, SourceError, Store, Via, ZigHash, zig_fetch};

const LIMIT: std::time::Duration = std::time::Duration::from_secs(60);
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

const COMMIT: &str = "63e36e934e8f2bedf645303a90b64098e2af6c8f";
/// The archive of `fixture` (pinned in the unit test too).
const SHA256: &str = "1095d3f78d352db796c0dc81030f69a547440cd912fe0e95e1dd975cb7a234fd";
const ZIG_HASH: &str = "N-V-__8AAA8AAABTzqy0ZMCn36mHMaTo8ISmsoNvvGZ_NZla";

fn fixture(root: &Path) {
    std::fs::create_dir_all(root.join("d/e")).unwrap();
    std::fs::write(root.join("a.txt"), "hi\n").unwrap();
    std::fs::write(root.join("d/run.sh"), "#!/bin/sh\n").unwrap();
    std::fs::set_permissions(
        root.join("d/run.sh"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();
    std::os::unix::fs::symlink("../a.txt", root.join("d/link")).unwrap();
    std::fs::write(root.join("d/e/f"), "x\n").unwrap();
}

fn url() -> GitUrl {
    "https://example.com/r.git".parse().unwrap()
}

fn commit() -> GitSha {
    COMMIT.parse().unwrap()
}

/// A `zig` that copies `tree` to `$ZIG_GLOBAL_CACHE_DIR/tmp/.tmp-x` and
/// prints Zig's listing of the fixture, after checking its arguments.
fn fake_zig(dir: &Path, tree: &Path) -> std::path::PathBuf {
    let listing = "\
file: 1fcce486437faf7ffd355efd191eeefcbe7d38a602805784db736b4ef6733f7e: a.txt
file: c2443e13a2637621cc2ef916077a6b84aef961520df2dd06520953aa4cd3a992: d/e/f
link: 33cb744b9b590eeeff856d45b5baad17ef227cc2d024777956df32435e5c21e1: d/link
file: 308cc4ff65bcbb85f2cf2047cd1bb3e4526242371fb37aaf49c36f9786828b69: d/run.sh
";
    let script = format!(
        r#"#!/bin/sh
set -e
[ "$1 $2 $3" = "fetch --debug-hash git+https://example.com/r.git#{COMMIT}" ] || {{ echo "bad args: $*" >&2; exit 2; }}
mkdir -p "$ZIG_GLOBAL_CACHE_DIR/tmp" "$ZIG_GLOBAL_CACHE_DIR/p"
cp -a '{tree}' "$ZIG_GLOBAL_CACHE_DIR/tmp/.tmp-x"
: > "$ZIG_GLOBAL_CACHE_DIR/p/{ZIG_HASH}.tar.gz"
printf '%s' '{listing}'
echo {ZIG_HASH}
"#,
        tree = tree.display()
    );
    let zig = dir.join("zig");
    std::fs::write(&zig, script).unwrap();
    std::fs::set_permissions(&zig, std::fs::Permissions::from_mode(0o755)).unwrap();
    zig
}

#[test]
fn from_dir_stores_the_canonical_archive() {
    let (tree, store_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    fixture(tree.path());
    let store = Store::new(store_dir.path().to_path_buf());
    let want: Sha256 = SHA256.parse().unwrap();
    let got = store.from_dir(tree.path(), &url(), commit(), None).unwrap();
    assert_eq!(got.sha256, want);
    assert!(store.path(&want).is_file());
    // Pinned and present: nothing to do, even without the tree.
    let again = store
        .from_dir(Path::new("/nonexistent"), &url(), commit(), Some(want))
        .unwrap();
    assert_eq!(again.sha256, want);
}

#[test]
fn a_different_archive_is_refused_and_not_stored() {
    let (tree, store_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    fixture(tree.path());
    let store = Store::new(store_dir.path().to_path_buf());
    let wrong = Sha256::of(b"something else");
    let err = store
        .from_dir(tree.path(), &url(), commit(), Some(wrong))
        .unwrap_err();
    assert!(matches!(err, SourceError::Mismatch { .. }), "{err}");
    let left: Vec<_> = std::fs::read_dir(store_dir.path().join("git"))
        .unwrap()
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn zig_fetch_checks_and_archives_zigs_checkout() {
    let (tree, bin, store_dir) = (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
        tempfile::tempdir().unwrap(),
    );
    fixture(tree.path());
    let zig = fake_zig(bin.path(), tree.path());
    let store = Store::new(store_dir.path().to_path_buf());
    let zig_hash: ZigHash = ZIG_HASH.parse().unwrap();
    let got = store
        .fetch(
            &zig,
            LIMIT,
            &url(),
            commit(),
            Pins {
                sha256: Some(SHA256.parse().unwrap()),
                zig_hash: Some(&zig_hash),
            },
        )
        .unwrap();
    assert_eq!(got.sha256.to_string(), SHA256);
    assert_eq!(got.zig_hash, Some(zig_hash));
    assert_eq!(got.via, Via::Zig);
    // Zig's scratch cache is gone; only the archive is left.
    let names: Vec<String> = std::fs::read_dir(store_dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, vec!["git".to_string()]);

    // A different Zig hash pinned: refused before anything is archived.
    let other_store = tempfile::tempdir().unwrap();
    let err = Store::new(other_store.path().to_path_buf())
        .fetch(
            &zig,
            LIMIT,
            &url(),
            commit(),
            Pins {
                sha256: None,
                zig_hash: Some(&"N-V-other".parse().unwrap()),
            },
        )
        .unwrap_err();
    assert!(matches!(err, SourceError::ZigMismatch { .. }), "{err}");

    // A checkout that differs from Zig's listing: refused.
    std::fs::write(tree.path().join("a.txt"), "tampered\n").unwrap();
    let other_store = tempfile::tempdir().unwrap();
    let err = Store::new(other_store.path().to_path_buf())
        .fetch(&zig, LIMIT, &url(), commit(), Pins::default())
        .unwrap_err();
    assert!(matches!(err, SourceError::Listing { .. }), "{err}");
}

fn script(dir: &Path, body: &str) -> std::path::PathBuf {
    let zig = dir.join("zig");
    std::fs::write(&zig, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&zig, std::fs::Permissions::from_mode(0o755)).unwrap();
    zig
}

// (Store::fetch falls back to gix when zig fails, which needs the network:
// zig's failures are tested on zig_fetch itself.)
#[test]
fn a_failing_zig_is_an_error() {
    let (bin, cache) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let zig = script(
        bin.path(),
        "echo 'error: TlsInitializationFailed' >&2\nexit 1",
    );
    let err = zig_fetch(&zig, cache.path(), &url(), commit(), LIMIT).unwrap_err();
    assert!(matches!(err, SourceError::ZigFailed { .. }), "{err}");
    assert!(err.to_string().contains("TlsInitializationFailed"), "{err}");
}

#[test]
fn a_slow_zig_is_stopped() {
    let (bin, cache) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    let zig = script(bin.path(), "exec sleep 30");
    let started = std::time::Instant::now();
    let err = zig_fetch(
        &zig,
        cache.path(),
        &url(),
        commit(),
        std::time::Duration::from_millis(300),
    )
    .unwrap_err();
    assert!(matches!(err, SourceError::ZigTimeout { .. }), "{err}");
    assert!(started.elapsed() < std::time::Duration::from_secs(10));
}

#[tokio::test]
async fn serves_archives_by_sha256_and_nothing_else() {
    let (tree, store_dir) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
    fixture(tree.path());
    let store = Store::new(store_dir.path().to_path_buf());
    let sha256 = store
        .from_dir(tree.path(), &url(), commit(), None)
        .unwrap()
        .sha256;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(hartland::sources::serve(store.clone(), listener));

    hartland::http::client(); // installs the crypto provider
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let base = format!("http://{addr}");
    let body = std::fs::read(store.path(&sha256)).unwrap();

    let r = client
        .get(format!("{base}/git/{sha256}.tar"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.bytes().await.unwrap(), body);

    let r = client
        .head(format!("{base}/git/{sha256}.tar"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.headers()["content-length"].to_str().unwrap(),
        body.len().to_string()
    );

    let missing = Sha256::of(b"missing");
    for path in [
        format!("/git/{missing}.tar"),
        format!("/git/{sha256}"),
        format!("/git/{}.tar", sha256.to_string().to_uppercase()),
        "/git/..%2f..%2fetc%2fpasswd".to_string(),
        "/".to_string(),
        format!("/other/{sha256}.tar"),
    ] {
        let r = client.get(format!("{base}{path}")).send().await.unwrap();
        assert_eq!(r.status(), 404, "{path}");
    }
    let r = client
        .post(format!("{base}/git/{sha256}.tar"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}
