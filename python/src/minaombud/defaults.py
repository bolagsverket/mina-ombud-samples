import json
import os

def _locate_sample_data():
    path = os.environ.get("MINA_OMBUD_SAMPLE_DATA")
    if path:
        return path

    base = os.path.dirname(__file__)
    paths = [
        "data",
        "../data",
        f"{base}/../../../data",
    ]
    for f in paths:
        if os.path.isdir(f):
            return os.path.abspath(f)


def _find_sample_users():
    path = os.environ.get("MINA_OMBUD_SAMPLE_USER_DB")
    if path:
        return path

    paths = []
    if MINA_OMBUD_SAMPLE_DATA:
        paths.append(os.path.join(MINA_OMBUD_SAMPLE_DATA, "users.json"))
    paths.append("users.json")

    for f in paths:
        if os.path.exists(f):
            return os.path.abspath(f)


def _find_sample_keys():
    path = os.environ.get("MINA_OMBUD_SAMPLE_KEYS")
    if path:
        return path.split(",")

    paths = []
    if MINA_OMBUD_SAMPLE_DATA:
        paths.append(os.path.join(MINA_OMBUD_SAMPLE_DATA, "keys"))
    paths.append("keys.jwks")
    paths.append("key.jwk")
    paths.append("key.pem")

    existing = []
    for f in paths:
        if os.path.exists(f):
            existing.append(os.path.abspath(f))
    return existing


MINA_OMBUD_API_TOKEN_URL = os.environ.get(
    "MINA_OMBUD_API_TOKEN_URL",
    "https://auth-accept.minaombud.se/auth/realms/dfm-accept2/protocol/openid-connect/token",
)
MINA_OMBUD_API_URL = os.environ.get(
    "MINA_OMBUD_API_URL", "https://fullmakt-test.minaombud.se/dfm/formedlare/v2"
)

MINA_OMBUD_API_CLIENT_ID = os.environ.get(
    "MINA_OMBUD_API_CLIENT_ID", "mina-ombud-sample"
)
MINA_OMBUD_API_CLIENT_SECRET = os.environ.get(
    "MINA_OMBUD_API_CLIENT_SECRET", "3392d044-d0f2-491d-a40d-edda4f1361c0"
)

MINA_OMBUD_SAMPLE_PORT = int(os.environ.get("MINA_OMBUD_SAMPLE_PORT", "8000"))
MINA_OMBUD_SAMPLE_BIND = os.environ.get("MINA_OMBUD_SAMPLE_BIND", "0.0.0.0")

MINA_OMBUD_SAMPLE_DATA = _locate_sample_data()
MINA_OMBUD_SAMPLE_USER_DB = _find_sample_users()
MINA_OMBUD_SAMPLE_KEYS = _find_sample_keys()

MINA_OMBUD_SAMPLE_USER = os.environ.get("MINA_OMBUD_SAMPLE_USER")
MINA_OMBUD_SAMPLE_USER_PASSWORD = os.environ.get("MINA_OMBUD_SAMPLE_USER_PASSWORD")
MINA_OMBUD_SAMPLE_USER_SCOPE = os.environ.get("MINA_OMBUD_SAMPLE_USER_SCOPE", "self")

MINA_OMBUD_TREDJE_MAN = os.environ.get("MINA_OMBUD_TREDJE_MAN", "2120000829")

MINA_OMBUD_SAMPLE_SERVICE = os.environ.get(
    "MINA_OMBUD_SAMPLE_SERVICE", "mina-ombud-sample"
)

MINA_OMBUD_SAMPLE_ISSUER = os.environ.get(
    "MINA_OMBUD_SAMPLE_ISSUER", f"http://localhost"
)
_MINA_OMBUD_SAMPLE_AUDIENCE = os.environ.get("MINA_OMBUD_SAMPLE_AUDIENCE")
if _MINA_OMBUD_SAMPLE_AUDIENCE:
    MINA_OMBUD_SAMPLE_AUDIENCE = list(_MINA_OMBUD_SAMPLE_AUDIENCE.split(","))
else:
    MINA_OMBUD_SAMPLE_AUDIENCE = ["mina-ombud"]

MINA_OMBUD_SAMPLE_CLIENT_ID = (
    os.environ.get("MINA_OMBUD_SAMPLE_CLIENT_ID") or MINA_OMBUD_SAMPLE_AUDIENCE[0]
)
MINA_OMBUD_SAMPLE_CLIENT_SECRET = os.environ.get("MINA_OMBUD_SAMPLE_CLIENT_SECRET")

MINA_OMBUD_USER_CLAIMS = {
    "sub": "4fe3e84f-400f-4459-b4ca-ae0ffdfe3ed2",
    "https://claims.oidc.se/1.0/personalNumber": "198602262381",
    "name": "Beri Ylles",
    "given_name": "Beri",
    "family_name": "Ylles",
    "iss": "http://localhost",
    "aud": "mina-ombud"
}


def _init_user_claims():
    claims = os.environ.get("MINA_OMBUD_USER_CLAIMS")
    if claims:
        MINA_OMBUD_USER_CLAIMS.update(json.loads(claims))
    pnr = os.environ.get("MINA_OMBUD_USER_PNR")
    if pnr:
        MINA_OMBUD_USER_CLAIMS["https://claims.oidc.se/1.0/personalNumber"] = pnr


_init_user_claims()
