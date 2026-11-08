//! Keyrings: which builders a consumer trusts.
//!
//! A builder is a reusable workflow, pinned to commits, running on a
//! GitHub-hosted runner. Who called it does not matter.

use serde::{Deserialize, Serialize};

pub const ISSUER: &str = "https://token.actions.githubusercontent.com";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Builder {
    /// `owner/repo/.github/workflows/file.yml`
    pub workflow: String,
    /// Trusted commits of that workflow (full sha).
    pub commits: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Keyring {
    pub builders: Vec<Builder>,
}

/// The facts a verified token establishes about who signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Signer {
    pub workflow: String,
    pub commit: String,
    /// The calling repository and the commit it built (token `repository`
    /// and `sha` claims): GitHub's word for what source was built.
    pub repository: String,
    pub source_commit: Option<String>,
    pub run_id: String,
}

fn claim<'a>(c: &'a serde_json::Value, k: &str) -> Result<&'a str, String> {
    c.get(k).and_then(|v| v.as_str()).ok_or_else(|| format!("token has no {k} claim"))
}

impl Keyring {
    /// Checks verified claims: issuer, audience, hosted runner, trusted builder.
    pub fn accept(&self, claims: &serde_json::Value, audience: &str) -> Result<Signer, String> {
        if claim(claims, "iss")? != ISSUER {
            return Err("token not issued by GitHub Actions".to_string());
        }
        let aud_ok = match claims.get("aud") {
            Some(serde_json::Value::String(a)) => a == audience,
            Some(serde_json::Value::Array(a)) => a.len() == 1 && a[0].as_str() == Some(audience),
            _ => false,
        };
        if !aud_ok {
            return Err("token audience does not match the statement".to_string());
        }
        // Self-hosted runners can run the same workflow and get valid tokens.
        if claim(claims, "runner_environment")? != "github-hosted" {
            return Err("not built on a GitHub-hosted runner".to_string());
        }
        let job_ref = claim(claims, "job_workflow_ref")?;
        let job_sha = claim(claims, "job_workflow_sha")?;
        let workflow = job_ref.split_once('@').map(|(w, _)| w).ok_or("malformed job_workflow_ref")?;
        let trusted = self
            .builders
            .iter()
            .any(|b| b.workflow == workflow && b.commits.iter().any(|c| c == job_sha));
        if !trusted {
            return Err(format!("builder {workflow}@{job_sha} is not in the keyring"));
        }
        Ok(Signer {
            workflow: workflow.to_string(),
            commit: job_sha.to_string(),
            repository: claim(claims, "repository")?.to_string(),
            source_commit: claims.get("sha").and_then(|v| v.as_str()).map(str::to_string),
            run_id: claim(claims, "run_id")?.to_string(),
        })
    }
}
