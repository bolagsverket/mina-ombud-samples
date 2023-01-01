import json
import re
import time
from typing import Mapping, Any, Optional, List, Dict, Sequence

from minaombud.crypto import jose
from minaombud.crypto.jose import JOSEHeader
from minaombud.crypto.jwkset import JwkSet
from minaombud.model import Identitetstyp, Identitetsbeteckning

_USER_INFO_SCOPES = {
    "https://scopes.oidc.se/1.0/naturalPersonPnr": {
        "https://claims.oidc.se/1.0/personalNumber",
        "https://claims.oidc.se/1.0/coordinationNumber",
        "birtdate",
        "family_name",
        "given_name",
        "name",
    },
    "https://scopes.oidc.se/1.0/naturalPersonName": {
        "family_name",
        "given_name",
        "name",
    },
    "profile": {"family_name", "given_name", "name", "preferred_username"},
    "email": {"email", "email_verified"},
    "phone": {"phone_number", "phone_number_verified"},
}

_ID_TOKEN_CLAIMS = set()


def _init_id_token_claims():
    for s in _USER_INFO_SCOPES.values():
        _ID_TOKEN_CLAIMS.update(s)


_init_id_token_claims()


class Unauthorized(Exception):
    pass


class BadCredentials(Unauthorized):
    pass


class UserNotFound(BadCredentials):
    pass


class BadPassword(BadCredentials):
    pass


def auth_user(
    username: str,
    password: Optional[str],
    users: Mapping[str, Mapping[str, Any]],
    *,
    scope: Optional[List[str]] = None,
    issuer: Optional[str] = None,
    audience: Optional[Sequence[str]] = None,
    typ="ID",
    expiry_time=0,
    default_user: Optional[Mapping[str, Any]] = None,
    default_password: Optional[str] = None,
    client_id: Optional[str] = None,
):
    claims: Dict[str, Any] = {"sub": f"user:{username}"}

    if typ:
        claims["typ"] = typ

    if issuer:
        claims["iss"] = issuer

    if audience:
        claims["aud"] = audience[0] if len(audience) == 1 else audience
    if client_id:
        claims["azp"] = client_id

    if audience and len(audience) > 1:
        pass

    if scope:
        claims["scope"] = " ".join(scope)

    iat = int(time.time())
    claims["iat"] = iat

    if expiry_time:
        claims["exp"] = iat + expiry_time

    user = users.get(username, default_user)
    if user is None:
        user = users.get("_default")
        if user is None:
            raise UserNotFound(username)

    actual_password = user.get("_password", default_password)
    if actual_password != password:
        raise BadPassword()

    claims.update({k: v for k, v in user.items() if not k.startswith("_")})
    userid_claims = (
        "https://claims.oidc.se/1.0/personalNumber",
        "https://claims.oidc.se/1.0/coordinationNumber",
        "preferred_username",
    )

    if not any(c in claims for c in userid_claims):
        claims["preferred_username"] = username

    return claims


def issue_token_response(
    claims: Dict[str, Any],
    jwks: JwkSet,
    scope: List[str],
    expiry_time=0,
    typ: Optional[str] = None,
) -> Dict[str, Any]:
    claims = dict(claims)

    if typ:
        claims["typ"] = typ

    iat = claims.get("iat")
    if not iat:
        iat = int(time.time())
        claims["iat"] = iat

    if expiry_time:
        claims["exp"] = iat + expiry_time

    if scope:
        claims["scope"] = " ".join(scope)

    if typ == "Bearer":
        access_token_claims = claims
    else:
        access_token_claims = {
            k: v for k, v in claims.items() if k not in _ID_TOKEN_CLAIMS
        }
        access_token_claims["typ"] = "Bearer"

    token_response = {
        "token_type": "Bearer",
        "access_token": jose.sign(access_token_claims, jwks),
        "scope": " ".join(scope),
        "expires_in": expiry_time or 3600,
    }

    if "openid" in scope:
        token_response["id_token"] = jose.sign(claims, jwks)

    return token_response


def create_user_token(
    user: str,
    jwks: JwkSet,
    *,
    users: Optional[Mapping[str, Mapping[str, Any]]] = None,
    issuer: Optional[str] = None,
    audience: Optional[Sequence[str]] = None,
    client_id: Optional[str] = None,
    expiry_time=0,
) -> str:
    if user.startswith("base64:"):
        user = user[7:]
        if user.count(".") == 2:
            # Serialized JWS
            return user

        if user.count(".") == 1:
            # Serialized JWT
            protected, payload = user.split(".")
            hdr = JOSEHeader.from_base64(protected)
            return jose.sign(payload, jwks, hdr)

        return jose.sign(user, jwks)

    if user.startswith("{"):
        # JSON user claims
        claims = json.loads(user)
    else:
        # CSV: username[,typ],first name,last name
        parts = [u.strip() for u in user.split(",")]
        username = parts.pop(0)
        idtyp = None
        if parts:
            try:
                idtyp = Identitetstyp[parts[0]]
                parts.pop()
            except KeyError:
                pass

        if idtyp:
            identitet = Identitetsbeteckning(username.replace("-", ""), idtyp)
        elif re.match(r"^(19|20)\d{6}-?\d{4}$", username):
            identitet = Identitetsbeteckning.from_id(username.replace("-", ""))
        else:
            identitet = None

        claims = {}
        if identitet:
            username = identitet.id
            if identitet.typ == Identitetstyp.PNR:
                claims["https://claims.oidc.se/1.0/personalNumber"] = identitet.id
            elif identitet.typ == Identitetstyp.SAMNR:
                claims["https://claims.oidc.se/1.0/coordinationNumber"] = identitet.id
            else:
                claims["sub"] = f"{identitet.typ}:{identitet.id}"
        else:
            claims["preferred_username"] = username

        if users:
            claims = auth_user(
                username,
                "",
                users,
                issuer=issuer,
                audience=audience,
                expiry_time=expiry_time,
                default_user=claims,
                default_password="",
            )

        if len(parts) == 2:
            claims["name"] = parts[0] + " " + parts[1]
            claims["given_name"] = parts[0]
            claims["family_name"] = parts[1]
        elif parts == 1:
            claims["name"] = parts[0]

        if not any(p in claims for p in ("given_name", "family_name")):
            claims["given_name"] = "Test"
            claims["family_name"] = "Persson"

    if issuer and "iss" not in claims:
        claims["iss"] = issuer

    if audience and "aud" not in claims:
        claims["aud"] = audience if len(audience) > 1 else audience[0]
        if len(audience) > 1 and client_id:
            claims["azp"] = client_id

    if "iat" not in claims:
        claims["iat"] = int(time.time())

    if expiry_time and "exp" not in claims:
        claims["exp"] = claims["int"] + expiry_time

    return jose.sign(claims, jwks)


def load_user_database(f):
    userid_claims = (
        "preferred_username",
        "https://claims.oidc.se/1.0/personalNumber",
        "https://claims.oidc.se/1.0/coordinationNumber",
        "sub",
        "nickname",
        "name",
    )

    user_data = json.load(f)
    if isinstance(user_data, list):
        by_id = {}
        for u in user_data:
            k = next(u[k] for k in userid_claims if k in u)
            by_id[k] = u
        return by_id
    else:
        return user_data
