//! Keyrings: which builders a consumer trusts.
//!
//! A builder is a reusable workflow, pinned to commits, running on a
//! GitHub-hosted runner. Who called it does not matter.

use crate::attest::Audience;
use crate::digest::GitSha;
use monostate::MustBe;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, OneOrMany, SerializeDisplay, serde_as};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("token audience does not match the statement")]
    Audience,
    #[error("not built on a GitHub-hosted runner")]
    SelfHosted,
    #[error("builder {0}@{1} is not in the keyring")]
    Untrusted(Workflow, GitSha),
}

#[derive(Debug, thiserror::Error)]
#[error("malformed {what}: {input:?}")]
pub struct Malformed {
    what: &'static str,
    input: String,
}

/// `owner/repo/.github/workflows/file.yml`
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, SerializeDisplay, DeserializeFromStr,
)]
pub struct Workflow {
    repository: Repository,
    file: String,
}

impl FromStr for Workflow {
    type Err = Malformed;
    fn from_str(s: &str) -> Result<Workflow, Malformed> {
        let bad = || Malformed {
            what: "workflow path",
            input: s.to_string(),
        };
        let mut parts = s.splitn(3, '/');
        let (Some(owner), Some(repo), Some(file)) = (parts.next(), parts.next(), parts.next())
        else {
            return Err(bad());
        };
        if !file.starts_with(".github/workflows/") {
            return Err(bad());
        }
        Ok(Workflow {
            repository: format!("{owner}/{repo}").parse().map_err(|_| bad())?,
            file: file.to_string(),
        })
    }
}

impl fmt::Display for Workflow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.repository, self.file)
    }
}

/// `owner/name`
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, SerializeDisplay, DeserializeFromStr,
)]
pub struct Repository {
    owner: String,
    name: String,
}

impl FromStr for Repository {
    type Err = Malformed;
    fn from_str(s: &str) -> Result<Repository, Malformed> {
        let ok = |p: &str| {
            !p.is_empty()
                && p.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"-_.".contains(&c))
        };
        match s.split_once('/') {
            Some((owner, name)) if ok(owner) && ok(name) => Ok(Repository {
                owner: owner.to_string(),
                name: name.to_string(),
            }),
            _ => Err(Malformed {
                what: "repository",
                input: s.to_string(),
            }),
        }
    }
}

impl fmt::Display for Repository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.owner, self.name)
    }
}

/// `job_workflow_ref`: `<workflow>@<git ref>` (a branch, tag or commit).
#[derive(Clone, Debug, DeserializeFromStr)]
pub struct WorkflowRef {
    pub workflow: Workflow,
    pub git_ref: String,
}

impl FromStr for WorkflowRef {
    type Err = Malformed;
    fn from_str(s: &str) -> Result<WorkflowRef, Malformed> {
        let (w, r) = s.split_once('@').ok_or_else(|| Malformed {
            what: "job_workflow_ref",
            input: s.to_string(),
        })?;
        Ok(WorkflowRef {
            workflow: w.parse()?,
            git_ref: r.to_string(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RunnerEnvironment {
    GithubHosted,
    SelfHosted,
}

/// The GitHub Actions OIDC claims we rely on.
#[serde_as]
#[derive(Clone, Debug, Deserialize)]
pub struct Claims {
    #[allow(dead_code)]
    iss: MustBe!("https://token.actions.githubusercontent.com"),
    #[serde_as(as = "OneOrMany<_>")]
    aud: Vec<String>,
    runner_environment: RunnerEnvironment,
    job_workflow_ref: WorkflowRef,
    job_workflow_sha: GitSha,
    /// The calling repository and the commit it built: GitHub's word for
    /// what source was built.
    repository: Repository,
    sha: Option<GitSha>,
    run_id: String,
}

/// The facts a verified, trusted token establishes about who signed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Signer {
    pub workflow: Workflow,
    pub commit: GitSha,
    pub repository: Repository,
    pub source_commit: Option<GitSha>,
    pub run_id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RawKeyring", into = "RawKeyring")]
pub struct Keyring {
    builders: BTreeMap<Workflow, BTreeSet<GitSha>>,
}

#[derive(Serialize, Deserialize)]
struct RawKeyring {
    builders: Vec<RawBuilder>,
}

#[derive(Serialize, Deserialize)]
struct RawBuilder {
    workflow: Workflow,
    commits: BTreeSet<GitSha>,
}

impl From<RawKeyring> for Keyring {
    fn from(r: RawKeyring) -> Keyring {
        let mut builders: BTreeMap<Workflow, BTreeSet<GitSha>> = BTreeMap::new();
        for b in r.builders {
            builders.entry(b.workflow).or_default().extend(b.commits);
        }
        Keyring { builders }
    }
}

impl From<Keyring> for RawKeyring {
    fn from(k: Keyring) -> RawKeyring {
        RawKeyring {
            builders: k
                .builders
                .into_iter()
                .map(|(workflow, commits)| RawBuilder { workflow, commits })
                .collect(),
        }
    }
}

impl Keyring {
    pub fn trusting(workflow: Workflow, commits: impl IntoIterator<Item = GitSha>) -> Keyring {
        Keyring {
            builders: [(workflow, commits.into_iter().collect())].into(),
        }
    }

    /// Accepts verified claims from a trusted builder on a hosted runner,
    /// bound to `audience`.
    pub fn accept(&self, claims: &Claims, audience: &Audience) -> Result<Signer, TrustError> {
        if claims.aud != [audience.to_string()] {
            return Err(TrustError::Audience);
        }
        // Self-hosted runners can run the same workflow and get valid tokens.
        if claims.runner_environment != RunnerEnvironment::GithubHosted {
            return Err(TrustError::SelfHosted);
        }
        let workflow = &claims.job_workflow_ref.workflow;
        if !self
            .builders
            .get(workflow)
            .is_some_and(|c| c.contains(&claims.job_workflow_sha))
        {
            return Err(TrustError::Untrusted(
                workflow.clone(),
                claims.job_workflow_sha,
            ));
        }
        Ok(Signer {
            workflow: workflow.clone(),
            commit: claims.job_workflow_sha,
            repository: claims.repository.clone(),
            source_commit: claims.sha,
            run_id: claims.run_id.clone(),
        })
    }
}
