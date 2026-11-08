//! Package attestations: "building target T of repository R at commit C with
//! this builder produced these output files".
//!
//! Signed by the trusted builder after a remote-only attested build, so every
//! action in the target's closure was executed by the builder's sandboxed
//! proxy or came from a cache entry signed by a trusted builder. The source
//! repository and commit are checked against the token's own `repository`
//! and `sha` claims: GitHub vouches for them, not the statement.

use crate::attest::{STATEMENT_TYPE, Subject, check_hex};
use crate::jwt::Jwks;
use crate::keyring::{Keyring, Signer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PREDICATE_TYPE: &str = "https://github.com/nhawkes/hartland/attest/package/v0";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Package {
    /// buck2 target label, e.g. `packages//examples/hello:hello`.
    pub target: String,
    pub repository: String,
    pub commit: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageStatement {
    #[serde(rename = "_type")]
    pub type_: String,
    /// One per output file: name is the output's path relative to the
    /// target's output root, digest its sha256.
    pub subject: Vec<Subject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: Package,
}

impl PackageStatement {
    pub fn new(package: Package, outputs: BTreeMap<String, String>) -> PackageStatement {
        PackageStatement {
            type_: STATEMENT_TYPE.to_string(),
            subject: outputs
                .into_iter()
                .map(|(name, hash)| Subject { name, digest: [("sha256".to_string(), hash)].into() })
                .collect(),
            predicate_type: PREDICATE_TYPE.to_string(),
            predicate: package,
        }
    }

    pub fn check(&self) -> Result<(), String> {
        if self.type_ != STATEMENT_TYPE || self.predicate_type != PREDICATE_TYPE {
            return Err("not a hartland package statement".to_string());
        }
        if self.subject.is_empty() {
            return Err("package statement has no outputs".to_string());
        }
        for s in &self.subject {
            check_hex(s.digest.get("sha256").ok_or("subject without sha256")?)?;
        }
        Ok(())
    }

    /// The digest attested for an output name, if any.
    pub fn digest_of(&self, name: &str) -> Option<&str> {
        self.subject.iter().find(|s| s.name == name).and_then(|s| s.digest.get("sha256")).map(String::as_str)
    }
}

pub fn statement_bytes(s: &PackageStatement) -> Vec<u8> {
    serde_json::to_vec(s).expect("statement serialises")
}

/// Verifies a package envelope: trusted builder, and the claimed source is the
/// one GitHub says the builder was run on.
pub fn verify(env: &crate::attest::Envelope, jwks: &Jwks, keyring: &Keyring) -> Result<(PackageStatement, Signer), String> {
    let (payload, signer) = crate::verify_signed(env, jwks, keyring)?;
    let st: PackageStatement = serde_json::from_slice(&payload).map_err(|e| format!("bad package statement: {e}"))?;
    st.check()?;
    if st.predicate.repository != signer.repository {
        return Err(format!("statement names {} but the builder ran for {}", st.predicate.repository, signer.repository));
    }
    if signer.source_commit.as_deref() != Some(st.predicate.commit.as_str()) {
        return Err(format!("statement names commit {} but the builder ran on {:?}", st.predicate.commit, signer.source_commit));
    }
    Ok((st, signer))
}
