from minaombud.client import MinaOmbudClient
from minaombud.crypto.jwkset import JwkSet
from minaombud.defaults import (
    MINA_OMBUD_API_CLIENT_ID,
    MINA_OMBUD_API_CLIENT_SECRET,
    MINA_OMBUD_API_TOKEN_URL,
    MINA_OMBUD_API_URL,
    MINA_OMBUD_SAMPLE_AUDIENCE,
    MINA_OMBUD_SAMPLE_ISSUER,
    MINA_OMBUD_SAMPLE_KEYS,
    MINA_OMBUD_SAMPLE_USER_DB
)
from minaombud.model import Identitetsbeteckning
from minaombud.user import (
    create_user_token,
    load_user_database
)


def _load_users():
    with open(MINA_OMBUD_SAMPLE_USER_DB) as f:
        return load_user_database(f)


KEYS = JwkSet.load(MINA_OMBUD_SAMPLE_KEYS)
USERS = _load_users()


def new_user_token(u: str):
    return create_user_token(u, jwks=KEYS, users=USERS,
                             audience=MINA_OMBUD_SAMPLE_AUDIENCE,
                             issuer=MINA_OMBUD_SAMPLE_ISSUER)


def new_client():
    return MinaOmbudClient(service="test_client.py", scope="user:self",
                           client_id=MINA_OMBUD_API_CLIENT_ID,
                           client_secret=MINA_OMBUD_API_CLIENT_SECRET,
                           url=MINA_OMBUD_API_URL,
                           token_url=MINA_OMBUD_API_TOKEN_URL)


def test_sok_fullmakter():
    client = new_client()
    user_token = new_user_token("198602262381")
    response = client.sok_fullmakter(tredjeman="2120000829",
                                     fullmaktshavare=Identitetsbeteckning.from_id("198602262381"),
                                     user_token=user_token)
    assert isinstance(response.fullmakter, list)


def test_sok_behorigheter():
    client = new_client()
    user_token = new_user_token("198602262381")
    response = client.sok_behorigheter(tredjeman="2120000829",
                                       fullmaktshavare=Identitetsbeteckning.from_id("198602262381"),
                                       user_token=user_token)
    assert isinstance(response.kontext, list)
