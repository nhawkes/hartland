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

async fn reply(req: reqwest::RequestBuilder) -> Result<Reply, String> {
    let resp = req.send().await.map_err(|e| e.to_string())?;
    let status = resp.status().as_u16();
    let headers = resp.headers().iter().map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string())).collect();
    let body = resp.bytes().await.map_err(|e| e.to_string())?.to_vec();
    Ok(Reply { status, body, headers })
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
        let r = reply(
            crate::http::client()
                .get(url)
                .query(&[("service", self.host.as_str()), ("scope", scope.as_str())])
                .basic_auth(user, Some(password)),
        )
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
        let r = reply(self.auth(crate::http::client().head(format!("{}/blobs/sha256:{hash}", self.base)))).await?;
        Ok(r.status == 200)
    }

    /// Reads a blob (following GHCR's redirect) and checks its digest.
    pub async fn get_blob(&self, hash: &str) -> Result<Vec<u8>, String> {
        let r = reply(self.auth(crate::http::client().get(format!("{}/blobs/sha256:{hash}", self.base)))).await?;
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
        reply(self.auth(crate::http::no_redirect_client().get(format!("{}/blobs/sha256:{hash}", self.base)))).await
    }

    /// Uploads a blob (monolithic POST then PUT) unless present. Returns its
    /// sha256 hex.
    pub async fn put_blob(&self, data: &[u8]) -> Result<String, String> {
        let hash = sha256_hex(data);
        if self.blob_exists(&hash).await? {
            return Ok(hash);
        }
        let r = reply(self.auth(crate::http::client().post(format!("{}/blobs/uploads/", self.base)))).await?;
        if r.status != 202 {
            return Err(format!("start upload: {} {}", r.status, String::from_utf8_lossy(&r.body)));
        }
        let loc = r.header("Location").ok_or("upload has no Location")?.to_string();
        let url = if loc.starts_with("http") { loc } else { format!("https://{}{loc}", self.host) };
        let sep = if url.contains('?') { '&' } else { '?' };
        let r = reply(
            self.auth(crate::http::client().put(format!("{url}{sep}digest=sha256:{hash}")))
                .header("Content-Type", "application/octet-stream")
                .body(data.to_vec()),
        )
        .await?;
        if r.status != 201 {
            return Err(format!("finish upload: {} {}", r.status, String::from_utf8_lossy(&r.body)));
        }
        Ok(hash)
    }

    /// Puts a manifest under `reference` (a tag or `sha256:<hex>`). Returns
    /// the manifest's digest as the registry reports it.
    pub async fn put_manifest(&self, reference: &str, media_type: &str, body: &[u8]) -> Result<String, String> {
        let r = reply(
            self.auth(crate::http::client().put(format!("{}/manifests/{reference}", self.base)))
                .header("Content-Type", media_type)
                .body(body.to_vec()),
        )
        .await?;
        if r.status != 201 {
            return Err(format!("put manifest {reference}: {} {}", r.status, String::from_utf8_lossy(&r.body)));
        }
        Ok(r.header("Docker-Content-Digest").map(str::to_string).unwrap_or_else(|| format!("sha256:{}", sha256_hex(body))))
    }

    pub async fn get_manifest(&self, reference: &str) -> Result<Reply, String> {
        reply(
            self.auth(crate::http::client().get(format!("{}/manifests/{reference}", self.base)))
                .header("Accept", format!("{MANIFEST_MEDIA_TYPE}, {INDEX_MEDIA_TYPE}")),
        )
        .await
    }

    /// OCI 1.1 referrers API. 404 means the registry does not support it.
    pub async fn referrers(&self, digest: &str) -> Result<Reply, String> {
        reply(self.auth(crate::http::client().get(format!("{}/referrers/{digest}", self.base)))).await
    }
}
