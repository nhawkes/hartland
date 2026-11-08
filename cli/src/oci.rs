//! A minimal async OCI distribution client, enough to use a registry (GHCR) as
//! a content-addressed store: blobs by sha256, manifests by tag or digest.
//!
//! No pacing on our side: requests go as fast as callers send them. When the
//! registry answers 429 it says how long to wait (GHCR: "retry-after: 17ms"
//! in the body, allowed 2000/minute). The first request to see it takes the
//! gate, sleeps exactly that, and resends while still holding it; the gate
//! reopens only when a reply comes back that is not a 429. Every request
//! passes the gate before sending, so nothing else goes out meanwhile, sleeps
//! never overlap, and the queue is released by one clean probe rather than a
//! herd. Requests whose 429 predates the reopening just go again.

use crate::digest::Sha256;
use bytes::Bytes;
use oci_spec::image::ImageManifest;
use reqwest::StatusCode;
use reqwest::header::HeaderMap;
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::fmt;
use std::future::Future;
use std::str::FromStr;
use std::time::Duration;
use tokio::sync::{Mutex, MutexGuard};
use tokio::time::Instant;

pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const ATTEMPTS: u32 = 8;

#[derive(Debug, thiserror::Error)]
pub enum OciError {
    #[error("{op}: {status} {body}")]
    Status {
        op: &'static str,
        status: StatusCode,
        body: String,
    },
    #[error("giving up after {ATTEMPTS} attempts: {0}")]
    GaveUp(String),
    #[error("blob {0} failed its digest check")]
    Corrupt(Sha256),
    #[error("upload has no Location")]
    NoLocation,
    #[error("registry login answered without a token")]
    NoToken,
    #[error("manifest is not valid: {0}")]
    Manifest(#[from] serde_json::Error),
}

/// A tag: `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, SerializeDisplay, DeserializeFromStr,
)]
pub struct Tag(String);

#[derive(Debug, thiserror::Error)]
#[error("not a valid OCI tag: {0:?}")]
pub struct BadTag(String);

impl FromStr for Tag {
    type Err = BadTag;
    fn from_str(s: &str) -> Result<Tag, BadTag> {
        let ok = matches!(s.as_bytes(), [first, rest @ ..]
            if (first.is_ascii_alphanumeric() || *first == b'_')
                && rest.len() < 128
                && rest.iter().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(c)));
        if ok {
            Ok(Tag(s.to_string()))
        } else {
            Err(BadTag(s.to_string()))
        }
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<Sha256> for Tag {
    /// A hex digest is a valid tag.
    fn from(d: Sha256) -> Tag {
        Tag(d.to_string())
    }
}

/// What a manifest is fetched or stored by.
#[derive(Clone, Debug)]
pub enum Reference {
    Tag(Tag),
    Digest(Sha256),
}

impl fmt::Display for Reference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Reference::Tag(t) => t.fmt(f),
            Reference::Digest(d) => write!(f, "sha256:{d}"),
        }
    }
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Reply {
    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body)
            .chars()
            .take(400)
            .collect()
    }

    fn expect(self, op: &'static str, ok: StatusCode) -> Result<Reply, OciError> {
        if self.status == ok {
            Ok(self)
        } else {
            Err(OciError::Status {
                op,
                status: self.status,
                body: self.body_text(),
            })
        }
    }

    /// How long a 429 asks us to wait: `Retry-After` seconds, or GHCR's
    /// "retry-after: 17.76ms" in the body.
    fn retry_after(&self) -> Option<Duration> {
        if let Some(s) = self
            .headers
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok()?.trim().parse::<f64>().ok())
        {
            return Some(Duration::from_secs_f64(s));
        }
        let body = String::from_utf8_lossy(&self.body);
        let rest = body.split("retry-after: ").nth(1)?;
        let end = rest
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(rest.len());
        let n: f64 = rest[..end].parse().ok()?;
        Some(Duration::from_secs_f64(if rest[end..].starts_with("ms") {
            n / 1000.0
        } else {
            n
        }))
    }
}

/// A reply and when it arrived (the 429 wait counts from then).
pub struct Received {
    pub reply: Reply,
    pub at: Instant,
}

/// The rate-limit gate; holds when it last reopened.
pub struct Gate {
    reopened: Mutex<Option<Instant>>,
}

impl Default for Gate {
    fn default() -> Gate {
        Gate::new()
    }
}

impl Gate {
    pub const fn new() -> Gate {
        Gate {
            reopened: Mutex::const_new(None),
        }
    }

    /// Sends with `send`, retrying 429 through the gate, 5xx and transport
    /// errors with exponential backoff.
    pub async fn send<F, Fut>(&'static self, send: F) -> Result<Reply, OciError>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = Result<Received, reqwest::Error>>,
    {
        let mut last = String::new();
        let mut held: Option<MutexGuard<'static, Option<Instant>>> = None;
        for attempt in 0..ATTEMPTS {
            if held.is_none() {
                drop(self.reopened.lock().await);
            }
            let backoff = Duration::from_millis(100 << attempt.min(6));
            match send().await {
                Ok(Received { reply, at }) if reply.status == StatusCode::TOO_MANY_REQUESTS => {
                    last = format!("429 {}", reply.body_text());
                    let gate = match held.take() {
                        Some(g) => g,
                        None => self.reopened.lock().await,
                    };
                    if gate.is_some_and(|t| t > at) {
                        continue; // another request's probe came back clean since
                    }
                    let wait = reply.retry_after().unwrap_or(backoff);
                    tracing::debug!(?wait, attempt, "429: gate closed, backing off");
                    tokio::time::sleep_until(at + wait).await;
                    held = Some(gate); // probe while holding
                }
                Ok(Received { reply, .. }) => {
                    if let Some(mut gate) = held.take() {
                        tracing::debug!(status = %reply.status, "probe clean, gate reopened");
                        *gate = Some(Instant::now());
                    }
                    if reply.status.is_server_error() {
                        tracing::warn!(status = %reply.status, attempt, "server error, retrying");
                        last = format!("{} {}", reply.status, reply.body_text());
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    return Ok(reply);
                }
                Err(e) => {
                    // No reply: a held gate stays held for the next probe.
                    tracing::warn!(error = %e, attempt, "transport error, retrying");
                    last = e.to_string();
                    tokio::time::sleep(backoff).await;
                }
            }
        }
        if let Some(mut gate) = held {
            *gate = Some(Instant::now());
        }
        Err(OciError::GaveUp(last))
    }
}

static GATE: Gate = Gate::new();

/// `make` builds a fresh request each try.
async fn send(make: impl Fn() -> reqwest::RequestBuilder) -> Result<Reply, OciError> {
    GATE.send(|| async {
        let resp = make().send().await?;
        let at = Instant::now();
        let (status, headers) = (resp.status(), resp.headers().clone());
        Ok(Received {
            reply: Reply {
                status,
                headers,
                body: resp.bytes().await?,
            },
            at,
        })
    })
    .await
}

#[derive(Clone)]
pub struct Registry {
    host: String,
    repo: String,
    bearer: Option<String>,
}

#[derive(serde::Deserialize)]
struct TokenReply {
    #[serde(alias = "access_token")]
    token: Option<String>,
}

impl Registry {
    /// `host` like `ghcr.io`, `repo` like `owner/hartland-cache`.
    pub fn new(host: &str, repo: &str) -> Registry {
        Registry {
            host: host.to_string(),
            repo: repo.to_string(),
            bearer: None,
        }
    }

    pub fn name(&self) -> String {
        format!("{}/{}", self.host, self.repo)
    }

    fn url(&self, path: impl fmt::Display) -> String {
        format!("https://{}/v2/{}/{path}", self.host, self.repo)
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.bearer {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    /// Exchanges basic credentials (e.g. GITHUB_ACTOR + GITHUB_TOKEN) for a
    /// registry bearer token scoped to pull and push on this repository.
    pub async fn login(&mut self, user: &str, password: &str) -> Result<(), OciError> {
        let url = format!("https://{}/token", self.host);
        let scope = format!("repository:{}:pull,push", self.repo);
        let r = send(|| {
            crate::http::client()
                .get(&url)
                .query(&[("service", self.host.as_str()), ("scope", scope.as_str())])
                .basic_auth(user, Some(password))
        })
        .await?
        .expect("registry login", StatusCode::OK)?;
        let t: TokenReply = serde_json::from_slice(&r.body)?;
        self.bearer = Some(t.token.ok_or(OciError::NoToken)?);
        Ok(())
    }

    pub async fn blob_exists(&self, hash: &Sha256) -> Result<bool, OciError> {
        let r = send(|| {
            self.auth(crate::http::client().head(self.url(format_args!("blobs/sha256:{hash}"))))
        })
        .await?;
        Ok(r.status == StatusCode::OK)
    }

    /// Reads a blob (following GHCR's redirect) and checks its digest.
    /// `None` if the registry does not have it.
    pub async fn get_blob(&self, hash: &Sha256) -> Result<Option<Bytes>, OciError> {
        let r = send(|| {
            self.auth(crate::http::client().get(self.url(format_args!("blobs/sha256:{hash}"))))
        })
        .await?;
        if r.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let r = r.expect("get blob", StatusCode::OK)?;
        if Sha256::of(&r.body) != *hash {
            return Err(OciError::Corrupt(*hash));
        }
        Ok(Some(r.body))
    }

    /// Uploads a blob unless present. Single-request monolithic upload (POST
    /// with digest and body); registries that do not support it answer 202
    /// with a session, which a PUT then completes.
    pub async fn put_blob(&self, data: Bytes) -> Result<Sha256, OciError> {
        let hash = Sha256::of(&data);
        if self.blob_exists(&hash).await? {
            return Ok(hash);
        }
        let r = send(|| {
            self.auth(crate::http::client().post(self.url("blobs/uploads/")))
                .query(&[("digest", format!("sha256:{hash}"))])
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(data.clone())
        })
        .await?;
        if r.status == StatusCode::CREATED {
            return Ok(hash);
        }
        let r = r.expect("start upload", StatusCode::ACCEPTED)?;
        let loc = r
            .headers
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(OciError::NoLocation)?;
        let url = if loc.starts_with("http") {
            loc.to_string()
        } else {
            format!("https://{}{loc}", self.host)
        };
        let sep = if url.contains('?') { '&' } else { '?' };
        send(|| {
            self.auth(crate::http::client().put(format!("{url}{sep}digest=sha256:{hash}")))
                .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
                .body(data.clone())
        })
        .await?
        .expect("finish upload", StatusCode::CREATED)?;
        Ok(hash)
    }

    /// Stores a manifest under `reference`; returns its digest.
    pub async fn put_manifest(
        &self,
        reference: &Reference,
        manifest: &ImageManifest,
    ) -> Result<Sha256, OciError> {
        let body = Bytes::from(serde_json::to_vec(manifest)?);
        send(|| {
            self.auth(crate::http::client().put(self.url(format_args!("manifests/{reference}"))))
                .header(reqwest::header::CONTENT_TYPE, MANIFEST_MEDIA_TYPE)
                .body(body.clone())
        })
        .await?
        .expect("put manifest", StatusCode::CREATED)?;
        Ok(Sha256::of(&body))
    }

    /// `None` if there is no such manifest.
    pub async fn get_manifest(
        &self,
        reference: &Reference,
    ) -> Result<Option<ImageManifest>, OciError> {
        let r = send(|| {
            self.auth(crate::http::client().get(self.url(format_args!("manifests/{reference}"))))
                .header(reqwest::header::ACCEPT, MANIFEST_MEDIA_TYPE)
        })
        .await?;
        if r.status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let r = r.expect("get manifest", StatusCode::OK)?;
        Ok(Some(serde_json::from_slice(&r.body)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(headers: &[(&'static str, &'static str)], body: &'static str) -> Reply {
        let mut h = HeaderMap::new();
        for (k, v) in headers {
            h.insert(*k, v.parse().unwrap());
        }
        Reply {
            status: StatusCode::TOO_MANY_REQUESTS,
            headers: h,
            body: Bytes::from_static(body.as_bytes()),
        }
    }

    #[test]
    fn retry_after_from_ghcr_body() {
        let r = reply(
            &[],
            r#"{"errors":[{"code":"TOOMANYREQUESTS","message":"retry-after: 17.763137ms, allowed: 2000/minute"}]}"#,
        );
        let d = r.retry_after().unwrap();
        assert!(d > Duration::from_millis(17) && d < Duration::from_millis(18));
    }

    #[test]
    fn retry_after_from_header_seconds() {
        assert_eq!(
            reply(&[("retry-after", "2")], "").retry_after(),
            Some(Duration::from_secs(2))
        );
        assert_eq!(reply(&[], "nothing here").retry_after(), None);
    }

    #[test]
    fn tags() {
        assert!("hartland-index".parse::<Tag>().is_ok());
        assert!(".hidden".parse::<Tag>().is_err());
        assert!("a/b".parse::<Tag>().is_err());
        assert!("x".repeat(129).parse::<Tag>().is_err());
    }

    /// A fake registry: 429 ("retry-after: 50ms") until `open_at`, then 200.
    struct Fake {
        open_at: Instant,
        sent: std::sync::Mutex<Vec<(Instant, StatusCode)>>,
    }

    impl Fake {
        async fn send(&self) -> Result<Received, reqwest::Error> {
            let now = Instant::now();
            let status = if now >= self.open_at {
                StatusCode::OK
            } else {
                StatusCode::TOO_MANY_REQUESTS
            };
            self.sent.lock().unwrap().push((now, status));
            tokio::time::sleep(Duration::from_millis(2)).await;
            Ok(Received {
                reply: Reply {
                    status,
                    headers: HeaderMap::new(),
                    body: Bytes::from_static(b"retry-after: 50ms"),
                },
                at: Instant::now(),
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn one_probe_at_a_time_and_no_herd() {
        static G: Gate = Gate::new();
        let start = Instant::now();
        // Rate-limited for 120 ms: needs three 50 ms back-offs to clear.
        let fake = std::sync::Arc::new(Fake {
            open_at: start + Duration::from_millis(120),
            sent: Default::default(),
        });
        let tasks: Vec<_> = (0..10)
            .map(|_| {
                let f = fake.clone();
                tokio::spawn(async move { G.send(|| f.send()).await })
            })
            .collect();
        for t in tasks {
            assert_eq!(t.await.unwrap().unwrap().status, StatusCode::OK);
        }
        let sent = fake.sent.lock().unwrap().clone();
        let first_ok = sent.iter().find(|(_, s)| *s == StatusCode::OK).unwrap().0;
        let before: Vec<_> = sent.iter().filter(|(t, _)| *t < first_ok).collect();
        // The initial burst of 10, then one probe per back-off: no herd.
        assert!(
            before.len() <= 10 + 3,
            "herd while rate-limited: {} requests before the first 200",
            before.len()
        );
        // Probes were spaced by the requested sleep: never overlapping.
        let probes: Vec<_> = before.iter().skip(10).map(|(t, _)| *t).collect();
        for w in probes.windows(2) {
            assert!(
                w[1] - w[0] >= Duration::from_millis(50),
                "sleeps overlapped: {probes:?}"
            );
        }
        // Nothing failed after the gate reopened.
        assert!(
            sent.iter()
                .all(|(t, s)| *t < first_ok || *s == StatusCode::OK)
        );
    }
}
