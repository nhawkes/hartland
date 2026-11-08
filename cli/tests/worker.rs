//! Scale-out end to end in one process: a coordinator pool and a worker over
//! iroh on local addresses, with certificates signed by the test-only RSA
//! key standing in for GitHub. The runner is a stand-in for the sandbox
//! executor (which CI exercises): it reads an input through the store,
//! writes an output through it, and records the result, as the executor
//! does.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hartland::cas::Blob;
use hartland::cert::{Identity, KeyAudience};
use hartland::digest::{ActionDigest, Digest};
use hartland::ghcr_store::{GhcrStore, Promote};
use hartland::jwt::Jwks;
use hartland::keyring::Keyring;
use hartland::l1::L1;
use hartland::proxy::{DiskStore, Store};
use hartland::reapi::re;
use hartland::worker::{Network, PeerTrust, Pool, Runner, WorkerConfig, run_worker};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

const KEY: &[u8] = include_bytes!("fixtures/test-only-rsa.pk8");
const KID: &str = "test-kid";
const WORKFLOW: &str = "nhawkes/hartland/.github/workflows/build.yml";
const COMMIT: &str = "8cf622e2e7dfaad7a1d7a08e12037a801c8fa8dc";
const REPO: &str = "someone/hartland-packages";

fn keypair() -> ring::signature::RsaKeyPair {
    ring::signature::RsaKeyPair::from_pkcs8(KEY).unwrap()
}

fn jwks() -> Jwks {
    let c: ring::rsa::PublicKeyComponents<Vec<u8>> = keypair().public().into();
    serde_json::from_value(
        json!({"keys": [{"kty": "RSA", "kid": KID, "n": B64.encode(c.n), "e": B64.encode(c.e)}]}),
    )
    .unwrap()
}

fn keyring() -> Keyring {
    Keyring::trusting(WORKFLOW.parse().unwrap(), [COMMIT.parse().unwrap()])
}

fn trust() -> PeerTrust {
    PeerTrust {
        keyring: keyring(),
        jwks: jwks(),
        repository: REPO.parse().unwrap(),
    }
}

fn token(claims: &Value) -> String {
    let h = B64.encode(serde_json::to_vec(&json!({"alg": "RS256", "kid": KID})).unwrap());
    let p = B64.encode(serde_json::to_vec(claims).unwrap());
    let input = format!("{h}.{p}");
    let kp = keypair();
    let mut sig = vec![0; kp.public().modulus_len()];
    kp.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &ring::rand::SystemRandom::new(),
        input.as_bytes(),
        &mut sig,
    )
    .unwrap();
    format!("{input}.{}", B64.encode(sig))
}

/// A key and a (test) certificate for it from a run of the builder.
fn identity(seed: u8, run_id: &str, event: &str, repository: &str) -> Identity {
    let id = Identity::from_seed([seed; 32]).unwrap();
    let claims = json!({
        "iss": "https://token.actions.githubusercontent.com",
        "aud": KeyAudience(&id.public()).to_string(),
        "repository": repository,
        "job_workflow_ref": format!("{WORKFLOW}@{COMMIT}"),
        "job_workflow_sha": COMMIT,
        "runner_environment": "github-hosted",
        "run_id": run_id,
        "event_name": event,
    });
    id.with_certificate(token(&claims))
}

/// Reads its input blob, writes `output of <input>`, records the result.
struct EchoRunner {
    store: Arc<dyn Store>,
    input: Digest,
}

#[async_trait::async_trait]
impl Runner for EchoRunner {
    async fn run(&self, action: ActionDigest) -> Result<re::ActionResult, String> {
        let input = self
            .store
            .get_blob(&self.input.hash)
            .await
            .ok_or("input not fetched")?;
        let out =
            Blob::new(format!("output of {}", String::from_utf8_lossy(input.data())).into_bytes());
        self.store.put_blob(&out).await.map_err(|e| e.to_string())?;
        let result = re::ActionResult {
            output_files: vec![re::OutputFile {
                path: "out".into(),
                digest: Some(out.digest().into()),
                ..Default::default()
            }],
            ..Default::default()
        };
        self.store
            .put_action_result(action, &result)
            .await
            .map_err(|e| e.to_string())?;
        Ok(result)
    }
}

struct Coordinator {
    pool: Arc<Pool>,
    store: Arc<GhcrStore>,
    addr: iroh::EndpointAddr,
    l1_dir: tempfile::TempDir,
    _dir: tempfile::TempDir,
    _ep: iroh::Endpoint,
}

async fn coordinator() -> Coordinator {
    let dir = tempfile::tempdir().unwrap();
    let l1_dir = tempfile::tempdir().unwrap();
    let local = DiskStore::open(dir.path().to_path_buf()).await.unwrap();
    let store = Arc::new(
        GhcrStore::new(local, vec![], None, keyring(), jwks()).with_first_tier(
            L1::open(l1_dir.path().to_path_buf()).await.unwrap(),
            Promote::All,
        ),
    );
    let me = identity(1, "100", "push", REPO);
    let ep = hartland::worker::bind(&me, Network::Local).await.unwrap();
    let addr = ep.addr();
    let pool = Pool::new(me, trust(), store.clone());
    tokio::spawn(pool.clone().serve(ep.clone()));
    Coordinator {
        pool,
        store,
        addr,
        l1_dir,
        _dir: dir,
        _ep: ep,
    }
}

fn worker_config(
    c: &Coordinator,
    id: Identity,
    coordinator_run: &str,
) -> (WorkerConfig, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let config = WorkerConfig {
        identity: id,
        coordinator: c.addr.clone(),
        coordinator_run: coordinator_run.into(),
        trust: trust(),
        dir: dir.path().to_path_buf(),
        slots: 2,
        idle: Duration::from_secs(2),
        network: Network::Local,
    };
    (config, dir)
}

async fn joined(pool: &Pool) -> bool {
    for _ in 0..100 {
        if pool.load().1 > 0 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_executes_signs_and_leaves_when_idle() {
    let c = coordinator().await;
    let input = Blob::new(&b"hello"[..]);
    c.store.put_blob(&input).await.unwrap();
    let action: ActionDigest = Digest::of(b"an action").into();

    let (config, _wdir) = worker_config(&c, identity(2, "200", "workflow_dispatch", REPO), "100");
    let input_digest = input.digest();
    let worker = tokio::spawn(run_worker(config, move |store| {
        Arc::new(EchoRunner {
            store,
            input: input_digest,
        }) as Arc<dyn Runner>
    }));
    assert!(joined(&c.pool).await, "worker did not join");

    let slot = c.pool.reserve().expect("a free worker slot");
    let (result, cacheable) = c.pool.execute(&slot, action).await.unwrap();
    drop(slot);
    assert!(cacheable);
    // The worker fetched its input from us and uploaded its output.
    let out = Digest::try_from(result.output_files[0].digest.as_ref()).unwrap();
    assert_eq!(
        c.store.get_blob(&out.hash).await.unwrap().data().as_ref(),
        b"output of hello"
    );
    c.store.put_worker_result(action, &result).await.unwrap();

    // Idle: the worker signs its batch, hands it over and exits.
    let executed = tokio::time::timeout(Duration::from_secs(20), worker)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(executed, 1);
    let batches = L1::open(c.l1_dir.path().to_path_buf())
        .await
        .unwrap()
        .load(&jwks(), &keyring())
        .await;
    assert_eq!(
        batches.len(),
        1,
        "the worker's signed batch is in the first tier"
    );
    assert_eq!(batches[0].results.len(), 1);
    assert_eq!(batches[0].results[0].action, action.id);
    assert!(batches[0].results[0].blobs.contains(&out.hash));
}

#[tokio::test(flavor = "multi_thread")]
async fn coordinator_refuses_runs_that_were_not_dispatched_or_are_elsewhere() {
    let c = coordinator().await;
    for (id, why) in [
        (identity(3, "300", "push", REPO), "not a dispatch"),
        (
            identity(
                4,
                "301",
                "workflow_dispatch",
                "someone-else/hartland-packages",
            ),
            "another repository",
        ),
    ] {
        let (config, _wdir) = worker_config(&c, id, "100");
        let outcome = run_worker(config, |store| {
            Arc::new(EchoRunner {
                store,
                input: Digest::of(b""),
            }) as Arc<dyn Runner>
        })
        .await;
        assert!(outcome.is_err(), "{why}: worker should be refused");
        assert_eq!(c.pool.load().1, 0, "{why}: no slots added");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn worker_refuses_a_coordinator_from_another_run() {
    let c = coordinator().await;
    let (config, _wdir) = worker_config(&c, identity(5, "400", "workflow_dispatch", REPO), "999");
    let outcome = run_worker(config, |store| {
        Arc::new(EchoRunner {
            store,
            input: Digest::of(b""),
        }) as Arc<dyn Runner>
    })
    .await;
    assert!(
        outcome.is_err(),
        "coordinator run 100 is not the dispatching run 999"
    );
}
