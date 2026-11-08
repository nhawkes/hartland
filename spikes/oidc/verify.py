"""Verify a GitHub Actions OIDC token read from stdin; print claims, never the token."""
import json, sys, time, urllib.request
import jwt

aud = sys.argv[1]
tok = sys.stdin.read().strip()
iss = "https://token.actions.githubusercontent.com"
jwks = jwt.PyJWKClient(iss + "/.well-known/jwks")
key = jwks.get_signing_key_from_jwt(tok)
header = jwt.get_unverified_header(tok)
result = {"alg": header.get("alg"), "kid": header.get("kid"), "token_length": len(tok)}
try:
    c = jwt.decode(tok, key.key, algorithms=["RS256"], audience=aud, issuer=iss)
    result["verified"] = True
    keep = ["aud", "iss", "sub", "repository", "repository_owner", "repository_visibility",
            "ref", "sha", "workflow_ref", "workflow_sha", "job_workflow_ref", "job_workflow_sha",
            "runner_environment", "event_name", "run_id", "run_attempt"]
    result["claims"] = {k: c.get(k) for k in keep}
    result["lifetime_seconds"] = c["exp"] - c["iat"]
    result["nbf_offset"] = c.get("nbf", c["iat"]) - c["iat"]
except Exception as e:
    result["verified"] = False
    result["error"] = repr(e)
try:
    jwt.decode(tok, key.key, algorithms=["RS256"], audience=aud + "x", issuer=iss)
    result["wrong_audience_rejected"] = False
except jwt.InvalidAudienceError:
    result["wrong_audience_rejected"] = True
# Is a verified signature still checkable after expiry (signature only)?
result["sig_valid_ignoring_exp"] = bool(jwt.decode(tok, key.key, algorithms=["RS256"], audience=aud,
                                                  issuer=iss, options={"verify_exp": False}))
result["jwks_kids"] = [k.key_id for k in jwks.get_signing_keys()]
print(json.dumps(result, indent=2))
