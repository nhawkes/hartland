//! Package attestations: "building target T of repository R at commit C with
//! this builder produced these output files".
//!
//! Signed by the trusted builder after a remote-only attested build, so every
//! action in the target's closure was executed by the builder's sandboxed
//! proxy or came from a cache entry signed by a trusted builder. The source
//! repository and commit are checked against the token's own `repository`
//! and `sha` claims: GitHub vouches for them, not the statement.

use crate::attest::{Envelope, Signed, Subject, SubjectDigest, VerifyError};
use crate::digest::{GitSha, Sha256};
use crate::jwt::Jwks;
use crate::keyring::{Keyring, Repository};
use monostate::MustBe;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    /// buck2 target label, e.g. `packages//examples/hello:hello`.
    pub target: String,
    pub repository: Repository,
    pub commit: GitSha,
}

/// One package's outputs, by name (path relative to the target's output
/// root), each with its digest. Never empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawPackageStatement", into = "RawPackageStatement")]
pub struct PackageStatement {
    pub package: Package,
    pub outputs: BTreeMap<String, Sha256>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RawPackageStatement {
    #[serde(rename = "_type")]
    type_: MustBe!("https://in-toto.io/Statement/v1"),
    subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    predicate_type: MustBe!("https://github.com/nhawkes/hartland/attest/package/v0"),
    predicate: Package,
}

#[derive(Debug, thiserror::Error)]
pub enum PackageError {
    #[error("package statement has no outputs")]
    NoOutputs,
    #[error("output {0} listed twice")]
    Duplicate(String),
}

impl TryFrom<RawPackageStatement> for PackageStatement {
    type Error = PackageError;
    fn try_from(r: RawPackageStatement) -> Result<PackageStatement, PackageError> {
        if r.subject.is_empty() {
            return Err(PackageError::NoOutputs);
        }
        let mut outputs = BTreeMap::new();
        for s in r.subject {
            if outputs.insert(s.name.clone(), s.digest.sha256).is_some() {
                return Err(PackageError::Duplicate(s.name));
            }
        }
        Ok(PackageStatement {
            package: r.predicate,
            outputs,
        })
    }
}

impl From<PackageStatement> for RawPackageStatement {
    fn from(p: PackageStatement) -> RawPackageStatement {
        RawPackageStatement {
            type_: MustBe!("https://in-toto.io/Statement/v1"),
            subject: p
                .outputs
                .into_iter()
                .map(|(name, sha256)| Subject {
                    name,
                    digest: SubjectDigest { sha256 },
                })
                .collect(),
            predicate_type: MustBe!("https://github.com/nhawkes/hartland/attest/package/v0"),
            predicate: p.package,
        }
    }
}

impl PackageStatement {
    pub fn new(
        package: Package,
        outputs: BTreeMap<String, Sha256>,
    ) -> Result<PackageStatement, PackageError> {
        if outputs.is_empty() {
            return Err(PackageError::NoOutputs);
        }
        Ok(PackageStatement { package, outputs })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a package statement serialises")
    }
}

/// Verifies a package envelope: trusted builder, and the claimed source is the
/// one GitHub says the builder was run on.
pub fn verify(
    env: &Envelope,
    jwks: &Jwks,
    keyring: &Keyring,
) -> Result<Signed<PackageStatement>, VerifyError> {
    let signed: Signed<PackageStatement> = env.verify(jwks, keyring)?;
    let (claimed, signer) = (&signed.statement.package, &signed.signer);
    if claimed.repository != signer.repository {
        return Err(VerifyError::WrongRepository {
            claimed: claimed.repository.to_string(),
            actual: signer.repository.to_string(),
        });
    }
    if signer.source_commit != Some(claimed.commit) {
        return Err(VerifyError::WrongCommit {
            claimed: claimed.commit,
            actual: signer.source_commit,
        });
    }
    Ok(signed)
}
