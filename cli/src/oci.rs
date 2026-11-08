//! A minimal async OCI distribution client, enough to use a registry (GHCR) as
//! a content-addressed store: blobs by sha256, manifests by tag or digest, and
//! the OCI 1.1 referrers query.

use crate::attest::sha256_hex;

pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

#[derive(Clone)]
pub struct Registry {
    host: String,
    base: String,
    repo: String,
    bearer: Option<String>,
}

pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
    pub headers: Vec<(String, String)>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

const ATTEMPTS: u32 = 8;

/// No pacing on our side: requests go as fast as callers send them. When the
/// registry answers 429 it says how long to wait (GHCR: "retry-after: 17ms"
/// in the body, allowed 2000/minute). The first request to see it takes this
/// gate, sleeps exactly that, and resends while still holding it; the gate
/// reopens only when a reply comes back that is not a 429. Every request
/// passes the gate before sending, so nothing else goes out meanwhile, sleeps
/// never overlap, and the queue is released by one clean probe rather than a
/// herd. Requests whose 429 predates the reopening just go again.
pub struct Gate {
    /// When the gate last reopened after a clean probe.
    reopened: tokio::sync::Mutex<Option<tokio::time::Instant>>,
}

type Held = tokio::sync::MutexGuard<'static, Option<tokio::time::Instant>>;

impl Gate {
    pub const fn new() -> Gate {
        Gate { reopened: tokio::sync::Mutex::const_new(None) }
    }
}

static GATE: Gate = Gate::new();

/// A reply plus when it arrived; `Err` is a transport failure.
type Sent = Result<(Reply, tokio::time::Instant), String>;

/// Sends with `send`, retrying 429 through the gate, 5xx and transport errors
/// with exponential backoff.
async fn retrying<F, Fut>(gate: &'static Gate, send: F) -> Result<Reply, String>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Sent>,
{
    let mut last = String::new();
    let mut held: Option<Held> = None;
    let reopen = |held: &mut Option<Held>| {
        if let Some(mut g) = held.take() {
            *g = Some(tokio::time::Instant::now());
        }
    };
    for attempt in 0..ATTEMPTS {
        if held.is_none() {
            drop(gate.reopened.lock().await);
        }
        let backoff = std::time::Duration::from_millis(100 << attempt.min(6));
        match send().await {
            Ok((r, received)) if r.status == 429 => {
                last = format!("429 {}", String::from_utf8_lossy(&r.body));
                let g = match held.take() {
                    Some(g) => g,
                    None => gate.reopened.lock().await,
                };
                if g.is_some_and(|t| t > received) {
                    continue; // another request's probe came back clean since
                }
                let wait = retry_after(&r).unwrap_or(backoff);
                tracing::debug!(?wait, attempt, "429: gate closed, backing off");
                tokio::time::sleep_until(received + wait).await;
                held = Some(g); // probe while holding
            }
            Ok((r, _)) => {
                if held.is_some() {
                    tracing::debug!(status = r.status, "probe clean, gate reopened");
                }
                reopen(&mut held);
                if (500..600).contains(&r.status) {
                    tracing::warn!(status = r.status, attempt, "server error, retrying");
                    last = format!("{} {}", r.status, String::from_utf8_lossy(&r.body));
                    tokio::time::sleep(backoff).await;
                    continue;
                }
                return Ok(r);
            }
            Err(e) => {
                // No reply: a held gate stays held for the next probe.
                tracing::warn!(error = %e, attempt, "transport error, retrying");
                last = e;
                tokio::time::sleep(backoff).await;
            }
        }
    }
    reopen(&mut held);
    Err(format!("giving up after {ATTEMPTS} attempts: {last}"))
}

fn retry_after(r: &Reply) -> Option<std::time::Duration> {
    if let Some(s) = r.header("Retry-After").and_then(|v| v.trim().parse::<f64>().ok()) {
        return Some(std::time::Duration::from_secs_f64(s));
    }
    // GHCR puts it in the body: "retry-after: 17.76ms".
    let body = String::from_utf8_lossy(&r.body);
    let rest = body.split("retry-after: ").nth(1)?;
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let n: f64 = num.parse().ok()?;
    let unit = &rest[num.len()..];
    Some(std::time::Duration::from_secs_f64(if unit.starts_with("ms") { n / 1000.0 } else { n }))
}

/// `make` builds a fresh request each try.
async fn reply_with(make: impl Fn() -> reqwest::RequestBuilder) -> Result<Reply, String> {
    retrying(&GATE, || async {
        let resp = make().send().await.map_err(|e| e.to_string())?;
        let received = tokio::time::Instant::now();
        let status = resp.status().as_u16();
        let headers = resp.headers().iter().map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())).collect();
        let body = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();
        Ok((Reply { status, body, headers }, received))
    })
    .await
}

impl Registry {
    /// `host` like `ghcr.io`, `repo` like `owner/hartland-cache`.
    pub fn new(host: &str, repo: &str) -> Registry {
        Registry { host: host.to_string(), base: format!("https://{host}/v2/{repo}"), repo: repo.to_string(), bearer: None }
    }

    /// Exchanges basic credentials (e.g. GITHUB_ACTOR + GITHUB_TOKEN) for a
    /// registry bearer token scoped to pull and push on this repository.
    pub async fn login(&mut self, user: &str, password: &str) -> Result<(), String> {
        let url = format!("https://{}/token", self.host);
        let scope = format!("repository:{}:pull,push", self.repo);
        let r = reply_with(|| {
            crate::http::client()
                .get(&url)
                .query(&[("service", self.host.as_str()), ("scope", scope.as_str())])
                .basic_auth(user, Some(password))
        })
        .await?;
        if r.status != 200 {
            return Err(format!("registry login failed: {} {}", r.status, String::from_utf8_lossy(&r.body)));
        }
        let v: serde_json::Value = serde_json::from_slice(&r.body).map_err(|e| e.to_string())?;
        let t = v.get("token").or_else(|| v.get("access_token")).and_then(|t| t.as_str()).ok_or("no token")?;
        self.bearer = Some(t.to_string());
        Ok(())
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.bearer {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    pub async fn blob_exists(&self, hash: &str) -> Result<bool, String> {
        let r = reply_with(|| self.auth(crate::http::client().head(format!("{}/blobs/sha256:{hash}", self.base)))).await?;
        Ok(r.status == 200)
    }

    /// Reads a blob (following GHCR's redirect) and checks its digest.
    pub async fn get_blob(&self, hash: &str) -> Result<Vec<u8>, String> {
        let r = reply_with(|| self.auth(crate::http::client().get(format!("{}/blobs/sha256:{hash}", self.base)))).await?;
        if r.status != 200 {
            return Err(format!("get blob {hash}: {}", r.status));
        }
        if sha256_hex(&r.body) != hash {
            return Err(format!("blob {hash} failed digest check"));
        }
        Ok(r.body)
    }

    /// The blob GET response itself, without following a redirect.
    pub async fn get_blob_raw(&self, hash: &str) -> Result<Reply, String> {
        reply_with(|| self.auth(crate::http::no_redirect_client().get(format!("{}/blobs/sha256:{hash}", self.base)))).await
    }

    /// Uploads a blob (monolithic POST then PUT) unless present. Returns its
    /// sha256 hex.
    pub async fn put_blob(&self, data: &[u8]) -> Result<String, String> {
        let hash = sha256_hex(data);
        if self.blob_exists(&hash).await? {
            return Ok(hash);
        }
        // Single-request monolithic upload (POST with digest and body): one
        // request instead of two. Registries that do not support it answer
        // 202 with a session, which we then complete with a PUT.
        let r = reply_with(|| {
            self.auth(crate::http::client().post(format!("{}/blobs/uploads/", self.base)))
                .query(&[("digest", format!("sha256:{hash}"))])
                .header("Content-Type", "application/octet-stream")
                .body(data.to_vec())
        })
        .await?;
        if r.status == 201 {
            return Ok(hash);
        }
        if r.status != 202 {
            return Err(format!("start upload: {} {}", r.status, String::from_utf8_lossy(&r.body)));
        }
        let loc = r.header("Location").ok_or("upload has no Location")?.to_string();
        let url = if loc.starts_with("http") { loc } else { format!("https://{}{loc}", self.host) };
        let sep = if url.contains('?') { '&' } else { '?' };
        let r = reply_with(|| {
            self.auth(crate::http::client().put(format!("{url}{sep}digest=sha256:{hash}")))
                .header("Content-Type", "application/octet-stream")
                .body(data.to_vec())
        })
        .await?;
        if r.status != 201 {
            return Err(format!("finish upload: {} {}", r.status, String::from_utf8_lossy(&r.body)));
        }
        Ok(hash)
    }

    /// Puts a manifest under `reference` (a tag or `sha256:<hex>`). Returns
    /// the manifest's digest as the registry reports it.
    pub async fn put_manifest(&self, reference: &str, media_type: &str, body: &[u8]) -> Result<String, String> {
        let r = reply_with(|| {
            self.auth(crate::http::client().put(format!("{}/manifests/{reference}", self.base)))
                .header("Content-Type", media_type)
                .body(body.to_vec())
        })
        .await?;
        if r.status != 201 {
            return Err(format!("put manifest {reference}: {} {}", r.status, String::from_utf8_lossy(&r.body)));
        }
        Ok(r.header("Docker-Content-Digest").map(str::to_string).unwrap_or_else(|| format!("sha256:{}", sha256_hex(body))))
    }

    pub async fn get_manifest(&self, reference: &str) -> Result<Reply, String> {
        reply_with(|| {
            self.auth(crate::http::client().get(format!("{}/manifests/{reference}", self.base)))
                .header("Accept", format!("{MANIFEST_MEDIA_TYPE}, {INDEX_MEDIA_TYPE}"))
        })
        .await
    }

    /// OCI 1.1 referrers API. 404 means the registry does not support it.
    pub async fn referrers(&self, digest: &str) -> Result<Reply, String> {
        reply_with(|| self.auth(crate::http::client().get(format!("{}/referrers/{digest}", self.base)))).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(headers: Vec<(&str, &str)>, body: &str) -> Reply {
        Reply { status: 429, body: body.as_bytes().to_vec(), headers: headers.into_iter().map(|(k, v)| (k.into(), v.into())).collect() }
    }

    #[test]
    fn retry_after_from_ghcr_body() {
        let r = reply(vec![], r#"{"errors":[{"code":"TOOMANYREQUESTS","message":"retry-after: 17.763137ms, allowed: 2000/minute"}]}"#);
        let d = retry_after(&r).unwrap();
        assert!(d > std::time::Duration::from_millis(17) && d < std::time::Duration::from_millis(18));
    }

    /// A fake registry: 429 ("retry-after: 50ms") until `open_at`, then 200.
    /// Records when each request was sent.
    struct Fake {
        open_at: tokio::time::Instant,
        sent: std::sync::Mutex<Vec<(tokio::time::Instant, u16)>>,
    }

    impl Fake {
        async fn send(&self) -> Sent {
            let now = tokio::time::Instant::now();
            let status = if now >= self.open_at { 200 } else { 429 };
            self.sent.lock().unwrap().push((now, status));
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
            Ok((Reply { status, body: b"retry-after: 50ms".to_vec(), headers: vec![] }, tokio::time::Instant::now()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn one_probe_at_a_time_and_no_herd() {
        static G: Gate = Gate::new();
        let start = tokio::time::Instant::now();
        // Rate-limited for 120 ms: needs three 50 ms back-offs to clear.
        let fake = std::sync::Arc::new(Fake { open_at: start + std::time::Duration::from_millis(120), sent: Default::default() });
        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let f = fake.clone();
                tokio::spawn(async move { retrying(&G, || f.send()).await })
            })
            .collect();
        for t in tasks {
            assert_eq!(t.await.unwrap().unwrap().status, 200);
        }
        let sent = fake.sent.lock().unwrap().clone();
        let first_ok = sent.iter().find(|(_, s)| *s == 200).unwrap().0;
        let before: Vec<_> = sent.iter().filter(|(t, _)| *t < first_ok).collect();
        // The initial burst of 10, then one probe per back-off: no herd.
        assert!(before.len() <= 10 + 3, "herd while rate-limited: {} requests before the first 200", before.len());
        // Probes were spaced by the requested sleep: never overlapping.
        let probes: Vec<_> = before.iter().skip(10).map(|(t, _)| *t).collect();
        for w in probes.windows(2) {
            assert!(w[1] - w[0] >= std::time::Duration::from_millis(50), "sleeps overlapped: {probes:?}");
        }
        // Nothing failed after the gate reopened.
        assert!(sent.iter().all(|(t, s)| *t < first_ok || *s == 200));
    }

    #[test]
    fn retry_after_from_header_seconds() {
        assert_eq!(retry_after(&reply(vec![("Retry-After", "2")], "")), Some(std::time::Duration::from_secs(2)));
        assert_eq!(retry_after(&reply(vec![], "nothing here")), None);
    }
}
