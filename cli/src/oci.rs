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
/// in the body, allowed 2000/minute); the waiter sleeps exactly that while
/// holding this gate, and every request passes the gate before sending, so
/// nothing new goes out meanwhile and sleeps never overlap.
static GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn wait_at_gate() {
    drop(GATE.lock().await);
}

/// Sleeps out the rest of a 429's retry-after under the gate. Time already
/// spent waiting for the gate counts, so concurrent 429s do not stack.
async fn back_off(received: tokio::time::Instant, wait: std::time::Duration) {
    let _held = GATE.lock().await;
    tokio::time::sleep_until(received + wait).await;
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

/// Sends, retrying 429 (sleeping what the registry asks, under the gate),
/// 5xx and transport errors (exponential backoff). `make` builds a fresh
/// request each try.
async fn reply_with(make: impl Fn() -> reqwest::RequestBuilder) -> Result<Reply, String> {
    let mut last = String::new();
    for attempt in 0..ATTEMPTS {
        wait_at_gate().await;
        let backoff = std::time::Duration::from_millis(100 << attempt.min(6));
        match make().send().await {
            Ok(resp) => {
                let received = tokio::time::Instant::now();
                let status = resp.status().as_u16();
                let headers = resp.headers().iter().map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())).collect();
                let body = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();
                let r = Reply { status, body, headers };
                if status == 429 {
                    last = format!("429 {}", String::from_utf8_lossy(&r.body));
                    back_off(received, retry_after(&r).unwrap_or(backoff)).await;
                    continue;
                }
                if (500..600).contains(&status) {
                    last = format!("{status} {}", String::from_utf8_lossy(&r.body));
                    tokio::time::sleep(backoff).await;
                    continue;
                }
                return Ok(r);
            }
            Err(e) => {
                last = e.to_string();
                tokio::time::sleep(backoff).await;
            }
        }
    }
    Err(format!("giving up after {ATTEMPTS} attempts: {last}"))
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

    #[tokio::test]
    async fn concurrent_429s_do_not_stack_and_block_new_requests() {
        let wait = std::time::Duration::from_millis(80);
        let start = tokio::time::Instant::now();
        // Two 429s received at the same moment, then a new request.
        let a = tokio::spawn(back_off(start, wait));
        let b = tokio::spawn(back_off(start, wait));
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let c = tokio::spawn(async move {
            wait_at_gate().await;
            tokio::time::Instant::now()
        });
        let (_, _, sent) = (a.await.unwrap(), b.await.unwrap(), c.await.unwrap());
        let total = start.elapsed();
        assert!(total >= wait, "slept less than requested: {total:?}");
        assert!(total < wait * 2, "sleeps stacked: {total:?}");
        assert!(sent - start >= wait, "a new request went out during the back-off");
    }

    #[test]
    fn retry_after_from_header_seconds() {
        assert_eq!(retry_after(&reply(vec![("Retry-After", "2")], "")), Some(std::time::Duration::from_secs(2)));
        assert_eq!(retry_after(&reply(vec![], "nothing here")), None);
    }
}
