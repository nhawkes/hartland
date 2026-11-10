//! Content identifiers, parsed once at the edge.
//!
//! A `Sha256` is 32 bytes, never a string that might be hex; a `GitSha` is a
//! full commit. Roles that share a representation get their own types
//! (`ActionId` for an action digest, `BatchId` for a signed envelope's
//! digest), so the compiler keeps them apart.

use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::fmt;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("not a {len}-byte lowercase hex digest: {input:?}")]
    Hex { len: usize, input: String },
    #[error("not a sha256 digest (want `sha256:<hex>`): {0:?}")]
    Prefixed(String),
    #[error("negative size {0}")]
    NegativeSize(i64),
    #[error("missing digest")]
    Missing,
}

fn parse_hex<const N: usize>(s: &str) -> Result<[u8; N], ParseError> {
    let err = || ParseError::Hex {
        len: N,
        input: s.chars().take(80).collect(),
    };
    // Lowercase only: one spelling per digest, so string forms compare.
    if s.len() != 2 * N || s.bytes().any(|c| c.is_ascii_uppercase()) {
        return Err(err());
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).map_err(|_| err())?;
    Ok(out)
}

/// A sha256 digest.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, SerializeDisplay, DeserializeFromStr,
)]
pub struct Sha256([u8; 32]);

impl Sha256 {
    pub const EMPTY: Sha256 = Sha256(hex_literal(
        b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ));

    pub fn of(data: &[u8]) -> Sha256 {
        let d = ring::digest::digest(&ring::digest::SHA256, data);
        Sha256(d.as_ref().try_into().expect("sha256 is 32 bytes"))
    }

    /// The OCI form, `sha256:<hex>`.
    pub fn oci(&self) -> oci_spec::image::Digest {
        format!("sha256:{self}")
            .parse()
            .expect("a sha256 digest is a valid OCI digest")
    }

    /// Parses the OCI form, refusing other algorithms.
    pub fn from_oci(d: &oci_spec::image::Digest) -> Result<Sha256, ParseError> {
        match d.algorithm() {
            oci_spec::image::DigestAlgorithm::Sha256 => d.digest().parse(),
            _ => Err(ParseError::Prefixed(d.to_string())),
        }
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The two-character shard for content-addressed directories.
    pub fn shard(&self) -> String {
        hex::encode(&self.0[..1])
    }
}

/// A sha256 computed incrementally.
pub struct Sha256Context(ring::digest::Context);

impl Default for Sha256Context {
    fn default() -> Sha256Context {
        Sha256Context(ring::digest::Context::new(&ring::digest::SHA256))
    }
}

impl Sha256Context {
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    pub fn finish(self) -> Sha256 {
        Sha256(
            self.0
                .finish()
                .as_ref()
                .try_into()
                .expect("sha256 is 32 bytes"),
        )
    }
}

const fn hex_literal(s: &[u8; 64]) -> [u8; 32] {
    const fn nibble(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("not lowercase hex"),
        }
    }
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = nibble(s[2 * i]) << 4 | nibble(s[2 * i + 1]);
        i += 1;
    }
    out
}

impl FromStr for Sha256 {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Sha256, ParseError> {
        parse_hex(s).map(Sha256)
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{self}")
    }
}

/// A full git commit id.
#[derive(
    Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, SerializeDisplay, DeserializeFromStr,
)]
pub struct GitSha([u8; 20]);

impl GitSha {
    pub fn bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// The abbreviated form: the first seven hex digits.
    pub fn short(&self) -> String {
        let mut s = self.to_string();
        s.truncate(7);
        s
    }
}

impl FromStr for GitSha {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<GitSha, ParseError> {
        parse_hex(s).map(GitSha)
    }
}

impl fmt::Display for GitSha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for GitSha {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

/// A REAPI digest: content hash and size, as checked at the gRPC boundary.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Digest {
    pub hash: Sha256,
    pub size: u64,
}

impl Digest {
    pub fn of(data: &[u8]) -> Digest {
        Digest {
            hash: Sha256::of(data),
            size: data.len() as u64,
        }
    }

    /// Does `data` have this digest?
    pub fn matches(&self, data: &[u8]) -> bool {
        data.len() as u64 == self.size && Sha256::of(data) == self.hash
    }
}

impl TryFrom<&crate::reapi::re::Digest> for Digest {
    type Error = ParseError;
    fn try_from(d: &crate::reapi::re::Digest) -> Result<Digest, ParseError> {
        Ok(Digest {
            hash: d.hash.parse()?,
            size: u64::try_from(d.size_bytes)
                .map_err(|_| ParseError::NegativeSize(d.size_bytes))?,
        })
    }
}

impl TryFrom<Option<&crate::reapi::re::Digest>> for Digest {
    type Error = ParseError;
    fn try_from(d: Option<&crate::reapi::re::Digest>) -> Result<Digest, ParseError> {
        d.ok_or(ParseError::Missing)?.try_into()
    }
}

impl From<Digest> for crate::reapi::re::Digest {
    fn from(d: Digest) -> crate::reapi::re::Digest {
        crate::reapi::re::Digest {
            hash: d.hash.to_string(),
            size_bytes: d.size as i64,
        }
    }
}

/// Newtypes over `Sha256` for digests with a role.
macro_rules! role {
    ($(#[$m:meta])* $name:ident) => {
        $(#[$m])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub Sha256);

        impl FromStr for $name {
            type Err = ParseError;
            fn from_str(s: &str) -> Result<$name, ParseError> {
                s.parse().map($name)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }
    };
}

role!(
    /// The digest of a serialised REAPI Action: the action cache key.
    ActionId
);
role!(
    /// The digest of a signed envelope: names one signed batch.
    BatchId
);

/// An action's digest: the cache key and the size that signed statements
/// record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ActionDigest {
    pub id: ActionId,
    pub size: u64,
}

impl From<Digest> for ActionDigest {
    fn from(d: Digest) -> ActionDigest {
        ActionDigest {
            id: ActionId(d.hash),
            size: d.size,
        }
    }
}

impl From<ActionDigest> for Digest {
    fn from(a: ActionDigest) -> Digest {
        Digest {
            hash: a.id.0,
            size: a.size,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_only_lowercase_full_length_hex() {
        assert_eq!(Sha256::EMPTY, Sha256::of(b""));
        assert_eq!(
            Sha256::EMPTY.to_string().parse::<Sha256>().unwrap(),
            Sha256::EMPTY
        );
        assert!(
            Sha256::EMPTY
                .to_string()
                .to_uppercase()
                .parse::<Sha256>()
                .is_err()
        );
        assert!("abc".parse::<Sha256>().is_err());
        assert!("2533ca1".parse::<GitSha>().is_err());
        assert!(
            "2533ca10bffb3653f6370154cfbf8ab19df47c95"
                .parse::<GitSha>()
                .is_ok()
        );
    }

    #[test]
    fn oci_round_trip() {
        let d = Sha256::of(b"x");
        assert_eq!(Sha256::from_oci(&d.oci()).unwrap(), d);
    }
}
