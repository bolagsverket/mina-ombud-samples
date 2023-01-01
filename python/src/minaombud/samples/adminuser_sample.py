#
# Sample demonstrating using the API acting as a user
# that is NOT a party to the Power of attorney.
#
# This is the case for persons that need to view
# the permissions granted to another part by a
# Power of attorney.
#
# For example a case handler at the third party.
#
# This type of API access is only granted to special
# API clients separate from clients where the end
# user represents a party to the Power of attorney.
#
import json
import time
import uuid

import requests

from minaombud import defaults
from minaombud.crypto import jose
from minaombud.crypto.jose import JOSEHeader
from minaombud.crypto.jwkset import JwkSet


def sample():
    ### 1. User claims
    iat = int(time.time())  # Time of issue
    exp = iat + 60  # Expiry time 1 minute
    user_claims = {
        "preferred_username": "casey",
        "https://claims.oidc.se/1.0/personalNumber": "200001152388",
        "name": "Case Handler",
        "given_name": "Case",
        "family_name": "Handler",
        "iat": iat,
        "exp": exp,
        "iss": "http://localhost",
        "aud": "mina-ombud",
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
        "scope": "user:other",
    }
    request_time = time.time()
    token_response = requests.post(token_url, token_request).json()
    assert token_response["token_type"] == "Bearer"
    access_token = token_response["access_token"]
    token_expires_at = request_time + token_response["expires_in"]

    ### 4. Invoke API
    api_url = defaults.MINA_OMBUD_API_URL
    fullmakter_request = {
        "tredjeman": ["2120000829"],
        "fullmaktshavare": {"id": "195004112354", "typ": "pnr"},
        "status": "GILTIG",
        "page": {"page": 0, "size": 100},
    }

    headers = {
        "authorization": f"Bearer {access_token}",
        "x-id-token": user_token,
        "x-service-name": "adminuser_sample",
        "x-request-id": str(uuid.uuid4()),
    }
    fullmakter_response = requests.post(
        f"{api_url}/sok/fullmakter", json=fullmakter_request, headers=headers
    )
    content_type = fullmakter_response.headers.get("content-type")
    if content_type == "application/json":
        print(json.dumps(fullmakter_response.json(), indent=2))
    else:
        for k, v in fullmakter_response.headers.items():
            print(f"{k}: {v}")
        print()
        print(fullmakter_response.text)


if __name__ == "__main__":
    sample()
