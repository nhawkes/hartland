//! A minimal OCI distribution client, enough to use a registry (GHCR) as a
//! content-addressed store: blobs by sha256, manifests by tag or digest, and
//! the OCI 1.1 referrers query.

use crate::attest::sha256_hex;

pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
pub const INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

pub struct Registry {
    agent: ureq::Agent,
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

impl Registry {
    /// `host` like `ghcr.io`, `repo` like `owner/hartland-cache`.
    pub fn new(host: &str, repo: &str) -> Registry {
        let agent: ureq::Agent = ureq::Agent::config_builder().http_status_as_error(false).build().into();
        Registry { agent, base: format!("https://{host}/v2/{repo}"), repo: repo.to_string(), bearer: None }
    }

    /// Exchanges basic credentials (e.g. GITHUB_ACTOR + GITHUB_TOKEN) for a
    /// registry bearer token scoped to pull and push on this repository.
    pub fn login(&mut self, host: &str, user: &str, password: &str) -> Result<(), String> {
        use base64::Engine as _;
        let basic = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        let url = format!("https://{host}/token?service={host}&scope=repository:{}:pull,push", self.repo);
        let r = self.agent.get(&url).header("Authorization", &format!("Basic {basic}")).go()?;
        if r.status != 200 {
            return Err(format!("registry login failed: {} {}", r.status, String::from_utf8_lossy(&r.body)));
        }
        let v: serde_json::Value = serde_json::from_slice(&r.body).map_err(|e| e.to_string())?;
        let t = v.get("token").or_else(|| v.get("access_token")).and_then(|t| t.as_str()).ok_or("no token")?;
        self.bearer = Some(t.to_string());
        Ok(())
    }

    fn auth<B>(&self, req: ureq::RequestBuilder<B>) -> ureq::RequestBuilder<B> {
        match &self.bearer {
            Some(t) => req.header("Authorization", &format!("Bearer {t}")),
            None => req,
        }
    }

    pub fn blob_exists(&self, hash: &str) -> Result<bool, String> {
        let r = self.auth(self.agent.head(&format!("{}/blobs/sha256:{hash}", self.base))).go()?;
        Ok(r.status == 200)
    }

    pub fn get_blob(&self, hash: &str) -> Result<Vec<u8>, String> {
        let r = self.auth(self.agent.get(&format!("{}/blobs/sha256:{hash}", self.base))).go()?;
        if r.status != 200 {
            return Err(format!("get blob {hash}: {}", r.status));
        }
        if sha256_hex(&r.body) != hash {
            return Err(format!("blob {hash} failed digest check"));
        }
        Ok(r.body)
    }

    /// Uploads a blob (monolithic POST then PUT). Returns its sha256 hex.
    pub fn put_blob(&self, data: &[u8]) -> Result<String, String> {
        let hash = sha256_hex(data);
        if self.blob_exists(&hash)? {
            return Ok(hash);
        }
        let r = self.auth(self.agent.post(&format!("{}/blobs/uploads/", self.base))).send_bytes(&[])?;
        if r.status != 202 {
            return Err(format!("start upload: {} {}", r.status, String::from_utf8_lossy(&r.body)));
        }
        let loc = r.header("Location").ok_or("upload has no Location")?.to_string();
        let url = if loc.starts_with("http") { loc } else { format!("https://{}{loc}", self.host()) };
        let sep = if url.contains('?') { '&' } else { '?' };
        let r = self
            .auth(self.agent.put(&format!("{url}{sep}digest=sha256:{hash}")))
            .header("Content-Type", "application/octet-stream")
            .send_bytes(data)?;
        if r.status != 201 {
            return Err(format!("finish upload: {} {}", r.status, String::from_utf8_lossy(&r.body)));
        }
        Ok(hash)
    }

    fn host(&self) -> &str {
        self.base.trim_start_matches("https://").split('/').next().unwrap_or("")
    }

    /// Puts a manifest under `reference` (a tag or `sha256:<hex>`). Returns
    /// the manifest's digest as the registry reports it.
    pub fn put_manifest(&self, reference: &str, media_type: &str, body: &[u8]) -> Result<String, String> {
        let r = self
            .auth(self.agent.put(&format!("{}/manifests/{reference}", self.base)))
            .header("Content-Type", media_type)
            .send_bytes(body)?;
        if r.status != 201 {
            return Err(format!("put manifest {reference}: {} {}", r.status, String::from_utf8_lossy(&r.body)));
        }
        Ok(r.header("Docker-Content-Digest").map(str::to_string).unwrap_or_else(|| format!("sha256:{}", sha256_hex(body))))
    }

    pub fn get_manifest(&self, reference: &str) -> Result<Reply, String> {
        self.auth(self.agent.get(&format!("{}/manifests/{reference}", self.base)))
            .header("Accept", &format!("{MANIFEST_MEDIA_TYPE}, {INDEX_MEDIA_TYPE}"))
            .go()
    }

    /// OCI 1.1 referrers API. 404 means the registry does not support it.
    pub fn referrers(&self, digest: &str) -> Result<Reply, String> {
        self.auth(self.agent.get(&format!("{}/referrers/{digest}", self.base))).go()
    }
}

/// Small helper trait so GET/HEAD (no body) and PUT/POST (bytes) share code.
pub trait Sendable {
    fn go(self) -> Result<Reply, String>;
}

fn reply(r: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> Result<Reply, String> {
    let mut r = r.map_err(|e| e.to_string())?;
    let status = r.status().as_u16();
    let headers = r
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();
    let body = r.body_mut().with_config().limit(1 << 30).read_to_vec().map_err(|e| e.to_string())?;
    Ok(Reply { status, body, headers })
}

impl Sendable for ureq::RequestBuilder<ureq::typestate::WithoutBody> {
    fn go(self) -> Result<Reply, String> {
        reply(self.call())
    }
}

pub trait SendBytes {
    fn send_bytes(self, data: &[u8]) -> Result<Reply, String>;
}

impl SendBytes for ureq::RequestBuilder<ureq::typestate::WithBody> {
    fn send_bytes(self, data: &[u8]) -> Result<Reply, String> {
        reply(self.send(data))
    }
}
