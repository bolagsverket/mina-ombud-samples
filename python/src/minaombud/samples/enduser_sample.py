#
# Sample demonstrating using the API acting as an end user
# that is a party to the Power of attorney.
#
# This is the standard case.
# A user wants to act using the permissions granted by a Power of attorney.
#
import base64
import functools
import json
import sys
import time
import uuid
from datetime import datetime

import requests

from minaombud import defaults
from minaombud.crypto import jose
from minaombud.crypto.jose import JOSEHeader
from minaombud.crypto.jwkset import JwkSet, RemoteJwkSet
from minaombud.model import JwsSig
from minaombud.util import parse_iso_datetime


def sample():
    ### 1. User claims
    iat = int(time.time())  # Time of issue
    exp = iat + 60 * 2      # Expiry time 2 minutes
    ssn = "198602262381"    # Social security number
    user_claims = {
        "https://claims.oidc.se/1.0/personalNumber": ssn,
        # "https://claims.oidc.se/1.0/coordinationNumber": ssn,
        "name": "Beri Ylles",
        "given_name": "Beri",
        "family_name": "Ylles",
        "iat": iat,
        "exp": exp,
        "iss": "http://localhost",
        "aud": "mina-ombud",
        "sub": "9ebe70e4-ca61-11ed-97ed-00155d52ccdb"
    }

    ### 2. Sign claims
    # a) Load signing key
    key_set = JwkSet.load(defaults.MINA_OMBUD_SAMPLE_KEYS)
    try:
        key = next(k for k in key_set.private_keys)
        assert key.kty == "RSA"
    except StopIteration:
        raise KeyError("No private key found")

    # b) Sign claims to get a JWS using compact serialization
    header = JOSEHeader(alg="RS256", kid=key.kid)
    user_token = jose.sign(user_claims, key, header)

    ### 3. Request API access token
    # The access token should be requested and reused for subsequent requests
    # until it expires at which point a new token must be requested.
    client_id = defaults.MINA_OMBUD_API_CLIENT_ID
    client_secret = defaults.MINA_OMBUD_API_CLIENT_SECRET
    token_url = defaults.MINA_OMBUD_API_TOKEN_URL
    token_request = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "user:self",
    }
    request_time = time.time()
    token_response = requests.post(token_url, token_request).json()
    assert token_response["token_type"] == "Bearer"
    access_token = token_response["access_token"]
    token_expires_at = request_time + token_response["expires_in"]

    ### 4. Invoke API
    api_url = defaults.MINA_OMBUD_API_URL
    behorigheter_request = {
        "tredjeman": defaults.MINA_OMBUD_TREDJE_MAN,  # Where the permission is used
        "fullmaktshavare": {"id": ssn, "typ": "pnr"},  # Holder of the permission
        "fullmaktsgivarroll": ["ORGANISATION"],  # Filter on issuer type
        # "fullmaktsgivare": { "id": "556...", "typ": "orgnr" },# Filter on issuer of permissions
        # "behorigheter": [                                     # Filter on specific permissions
        #     "ac94b31e-a17f-11ed-b19d-00155d41fac2"
        # ],
        "page": {"page": 0, "size": 100},  # Pagination
    }

    headers = {
        "authorization": f"Bearer {access_token}",
        "x-id-token": user_token,
        "x-service-name": "enduser_sample",
        "x-request-id": str(uuid.uuid4()),
    }
    behorigheter_response = requests.post(
        f"{api_url}/sok/behorigheter", json=behorigheter_request, headers=headers
    )
    content_type = behorigheter_response.headers.get("content-type")
    if content_type != "application/json":
        for kontext, v in behorigheter_response.headers.items():
            print(f"{kontext}: {v}", file=sys.stderr)
        print(file=sys.stderr)
        print(behorigheter_response.text, file=sys.stderr)
        return

    print(json.dumps(behorigheter_response.json(), indent=2))

    ### 5. Verify response signature and timestamp
    # When the permissions are passed on to other services/systems
    # instead of being used right away it is important to verify
    # the digital signature of the permissions in the receiving
    # service.
    #
    # This ensures the permissions have not been tampered with.
    #
    # This verification should take place in the receiving service.
    perr = functools.partial(print, file=sys.stderr)
    for kontext in behorigheter_response.json()["kontext"]:
        # a) Fetch key set
        #    In a real implementation the keys would be cached
        #    and only fetched when a new key is used.
        tredjeman: str = kontext["tredjeman"]
        assert tredjeman.isdigit()
        key_set = RemoteJwkSet(f"{api_url}/tredjeman/{tredjeman}/jwks")

        # b) Detach the embedded signature from the signed object.
        sig = kontext["_sig"]
        del kontext["_sig"]

        # c) Produce the canonical JSON representation of the payload
        canonical = json.dumps(
            kontext,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )

        # d) Encode UTF-8 representation of the JSON payload as Base 64-url
        payload = base64.urlsafe_b64encode(canonical.encode("utf-8")).rstrip(b"=")

        # e) Verify the detached signature against the canonical payload:
        #    sig["signature"] == signature(sig["protected"] + '.' + payload)
        valid = jose.verify_jws(payload, JwsSig.from_dict(sig), key_set)
        if not valid:
            perr("Signature verification failed")
            perr(f"- Header    : {sig['protected']}")
            perr(f"- Payload   : {payload.decode('ascii')}")
            perr(f"- Signature : {sig['signature']}")
            perr(json.dumps(kontext, ensure_ascii=False, indent=2, sort_keys=True))

        # f) Check timestamp of permissions.
        #    The tolerance is very application dependent.
        #    Here we accept up to 2 minutes old information.
        iso_timestamp = kontext["tidpunkt"]
        timestamp = parse_iso_datetime(iso_timestamp)
        now = datetime.now(timestamp.tzinfo)
        delta = now - timestamp
        if delta.total_seconds() > 2 * 60:
            perr(f"Expired: {iso_timestamp} : {delta}")
            perr(json.dumps(kontext, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    sample()
