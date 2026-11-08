"""Checks, before it is run, that a hartland binary is exactly what the
trusted builder compiled.

The coordinator compiles the CLI from source at the builder commit, then
requests one GitHub Actions OIDC token whose audience is
`hartland-binary:sha256:<digest of the binary>`. The binary and token travel
through the Actions cache, which any workflow in the repository can write, so
neither is trusted until this script has checked:

  * the token's RS256 signature, against hartland's archived GitHub keys;
  * issuer GitHub Actions, a GitHub-hosted runner;
  * job_workflow_ref is the builder workflow and job_workflow_sha is the
    builder commit this worker is running;
  * the repository is this worker's own;
  * the audience is the digest of these exact bytes.

Pure Python standard library only (RSA verification is one modular
exponentiation), so nothing outside the trusted runner image and hartland's
own source is involved.

Usage: verify-binary.py <jwks.json> <token-file> <binary> <workflow> <commit> <repository>
Exit status 0 if the binary may be run.
"""

import base64
import hashlib
import hmac
import json
import sys

ISSUER = "https://token.actions.githubusercontent.com"
# DER prefix of a PKCS#1 v1.5 DigestInfo for SHA-256.
SHA256_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def b64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def verify_rs256(token: str, jwks: dict) -> dict:
    header_b64, payload_b64, sig_b64 = token.split(".")
    header = json.loads(b64url(header_b64))
    if header.get("alg") != "RS256":
        raise ValueError(f"unsupported alg {header.get('alg')}")
    key = next((k for k in jwks["keys"] if k.get("kid") == header.get("kid")), None)
    if key is None or key.get("kty") != "RSA":
        raise ValueError(f"unknown signing key {header.get('kid')}")
    n = int.from_bytes(b64url(key["n"]), "big")
    e = int.from_bytes(b64url(key["e"]), "big")
    k = (n.bit_length() + 7) // 8
    sig = b64url(sig_b64)
    if len(sig) != k:
        raise ValueError("signature has the wrong length")
    em = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    digest = hashlib.sha256(f"{header_b64}.{payload_b64}".encode()).digest()
    t = SHA256_PREFIX + digest
    expected = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
    if not hmac.compare_digest(em, expected):
        raise ValueError("signature does not verify")
    return json.loads(b64url(payload_b64))


def check(jwks_path, token_path, binary_path, workflow, commit, repository) -> str:
    jwks = json.load(open(jwks_path))
    token = open(token_path).read().strip()
    claims = verify_rs256(token, jwks)
    with open(binary_path, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    problems = []
    if claims.get("iss") != ISSUER:
        problems.append(f"issuer {claims.get('iss')}")
    if claims.get("runner_environment") != "github-hosted":
        problems.append(f"runner {claims.get('runner_environment')}")
    if claims.get("job_workflow_ref", "").split("@")[0] != workflow:
        problems.append(f"workflow {claims.get('job_workflow_ref')}")
    if claims.get("job_workflow_sha") != commit:
        problems.append(f"builder commit {claims.get('job_workflow_sha')}")
    if claims.get("repository") != repository:
        problems.append(f"repository {claims.get('repository')}")
    if auds != [f"hartland-binary:sha256:{digest}"]:
        problems.append("audience is not this binary's digest")
    if problems:
        raise ValueError("; ".join(problems))
    return f"{digest} built by {workflow}@{commit} in run {claims.get('run_id')}"


if __name__ == "__main__":
    try:
        print(check(*sys.argv[1:7]))
    except Exception as e:  # any failure means: do not run this binary
        print(f"refused: {e}", file=sys.stderr)
        sys.exit(1)
