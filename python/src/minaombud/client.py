import cgi
from typing import Optional, Union, Dict, Type, Iterable, Collection
from uuid import UUID

import requests
from oauthlib.oauth2 import BackendApplicationClient
from requests import Response
from requests_oauthlib import OAuth2Session

from minaombud.crypto.jose import verify_embedded_jws
from minaombud.crypto.jwkset import RemoteJwkSet
from minaombud.model import (
    Identitetsbeteckning,
    HamtaBehorigheterRequest,
    FullmaktsgivareRoll,
    PageParameters,
    HamtaBehorigheterResponse,
    ApiError,
    ApiException,
    HamtaFullmakterRequest,
    HamtaFullmakterResponse,
    FullmaktStatus,
    FullmaktMetadataResponse,
)
from minaombud.serialization import A, encode_json


class _OAuth2SessionRequestingNewToken(OAuth2Session):
    """Backend client adaption of :class:`requests_oauthlib.OAuth2Session`.

    Implements token refresh by requesting a new access token when required
    using client credentials grant.
    """

    def refresh_token(self, token_url: str, **kwargs):
        refresh_token = kwargs.pop("refresh_token", None)
        if refresh_token:
            return super(_OAuth2SessionRequestingNewToken, self).refresh_token(
                refresh_token=refresh_token, **kwargs
            )

        kwargs.update(self.auto_refresh_kwargs)
        return self.fetch_token(self.auto_refresh_url, **kwargs)


def _parse_api_response(cls: Type[A], response: Response) -> A:
    if response.ok:
        return cls.from_json(response.content)

    content_type, _ = cgi.parse_header(response.headers.get("content-type", ""))
    if content_type.lower() == "application/json":
        obj = response.json()
        if isinstance(obj, dict):
            try:
                error = ApiError.from_dict(obj)
                raise ApiException(url=response.request.url, error=error)
            except (ValueError, TypeError, KeyError):
                pass

    response.raise_for_status()


class MinaOmbudClient:
    def __init__(
        self,
        *,
        service: str,
        scope: Union[str, Iterable[str]],
        client_id: str,
        client_secret: str,
        token_url="https://auth-accept.minaombud.se/auth/realms/dfm/protocol/openid-connect/token",
        url="https://fullmakt-test.minaombud.se/dfm/formedlare/v1",
    ):
        self.url = url
        self.scope = frozenset(scope.split(" ") if isinstance(scope, str) else scope)
        self.client_id = client_id
        self.client_secret = client_secret
        self.service = service
        self._session: Optional[OAuth2Session] = None
        self.token_url = token_url

        self.jwks_session = requests.Session()

        self.jwks: Dict[str, RemoteJwkSet] = dict()

    @property
    def session(self):
        if not self._session:
            client = BackendApplicationClient(
                client_id=self.client_id, scope=" ".join(self.scope)
            )
            auto_refresh_kwargs = {
                "client_secret": self.client_secret,
                "include_client_id": True,
            }

            def token_updater(_token):
                pass

            self._session = _OAuth2SessionRequestingNewToken(
                client_id=self.client_id,
                client=client,
                scope=client.scope,
                auto_refresh_url=self.token_url,
                auto_refresh_kwargs=auto_refresh_kwargs,
                token_updater=token_updater,
            )
            self._session.headers["accept"] = "application/json"
            self._session.headers["x-service-name"] = self.service
            self._session.fetch_token(self.token_url, client_secret=self.client_secret)

        return self._session

    def _user_token_header(self, user_token: Optional[str]) -> Dict[str, str]:
        must_exist = any(scope in self.scope for scope in ("user:self", "user:other"))
        must_not_exist = "user:any" in self.scope
        if must_exist and not user_token:
            raise ValueError(
                f"User identity token required with scope={' '.join(self.scope)}"
            )

        if must_not_exist and user_token:
            raise ValueError(
                f"User identity token not used with scope={' '.join(self.scope)}"
            )

        if not user_token:
            return {}

        return {"x-id-token": user_token}

    def get_jwk_set(self, tredjeman: str):
        try:
            return self.jwks[tredjeman]
        except KeyError:
            url = f"{self.url}/tredjeman/{tredjeman}/jwks"
            jwk_set = RemoteJwkSet(url, self.jwks_session)
            self.jwks[tredjeman] = jwk_set
            return jwk_set

    def _post(
        self, response_type: Type[A], path: str, body, user_token: Optional[str] = None
    ) -> A:
        headers = self._user_token_header(user_token)
        response = self.session.post(
            f"{self.url}{path}", headers=headers, json=encode_json(body)
        )
        return _parse_api_response(response_type, response)

    def _get(
        self, response_type: Type[A], path: str, user_token: Optional[str] = None
    ) -> A:
        headers = self._user_token_header(user_token)
        response = self.session.get(f"{self.url}{path}", headers=headers)
        return _parse_api_response(response_type, response)

    def sok_behorigheter(
        self,
        tredjeman: str,
        fullmaktshavare: Identitetsbeteckning,
        *,
        fullmaktsgivare: Optional[Identitetsbeteckning] = None,
        fullmaktsgivarroll: Optional[Collection[FullmaktsgivareRoll]] = None,
        behorigheter: Optional[Collection[str]] = None,
        user_token: Optional[str] = None,
        page=0,
        page_size=100,
    ) -> HamtaBehorigheterResponse:
        """Söker behörigheter för en fullmaktshavare.

        Svaret på sökningen är en lista med :class:`minaombud.model.Behorighetskontext`.

        En behörighetskontext

        Args:
            tredjeman: organisationsnummer för tredje man där behörigheterna gäller.
            fullmaktshavare: identitet på personen vars behörigheter begärs.
            fullmaktsgivare: ange en identitet om behörigheter begärs för en specifik fullmaktsgivare.
            behorigheter: en eller flera behörigheter som begärs (alla returneras om utelämnad)-
            user_token: en JWS som identifierar användaren som begär informationen.

        Returns:
            Response-objekt med behörighetskontexter.
        """
        body = HamtaBehorigheterRequest(
            tredjeman=tredjeman,
            fullmaktshavare=fullmaktshavare,
            fullmaktsgivare=fullmaktsgivare,
            fullmaktsgivarroll=fullmaktsgivarroll,
            behorigheter=behorigheter,
            page=PageParameters(page=page, size=page_size),
        )
        response = self._post(
            HamtaBehorigheterResponse, "/sok/behorigheter", body, user_token=user_token
        )

        for k in response.kontext:
            if not verify_embedded_jws(k, self.get_jwk_set(k.tredjeman)):
                raise ValueError(
                    f"Ogiltig signatur för behörighetskontext {k.tredjeman} {k.fullmaktsgivare.id} {k.fullmaktsgivarroll.value}"
                )

        return response

    def sok_fullmakter(
        self,
        request: Optional[HamtaFullmakterRequest] = None,
        *,
        tredjeman: Optional[Union[str, Collection[str]]] = None,
        fullmaktshavare: Optional[Identitetsbeteckning],
        fullmaktsgivare: Optional[Identitetsbeteckning] = None,
        fullmaktsgivarroll: Optional[Collection[FullmaktsgivareRoll]] = None,
        status: Optional[FullmaktStatus] = None,
        aterkallad: Optional[bool] = None,
        user_token: Optional[str] = None,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
    ) -> HamtaFullmakterResponse:

        if isinstance(tredjeman, str):
            tredjeman = [tredjeman]

        if request is None:
            request = HamtaFullmakterRequest()

        if tredjeman:
            request.tredjeman = tredjeman

        if fullmaktsgivare:
            request.fullmaktsgivare = fullmaktsgivare

        if fullmaktsgivarroll:
            request.fullmaktsgivarroll = fullmaktsgivarroll

        if fullmaktshavare:
            request.fullmaktshavare = fullmaktshavare

        if status:
            request.status = status

        if aterkallad is not None:
            request.aterkallad = aterkallad

        if page or page_size:
            request.page = PageParameters(page, page_size)

        if not (request.fullmaktshavare or request.fullmaktsgivare):
            raise ValueError("Fullmaktshavare och/eller fullmaktsgivare måste anges")

        return self._post(
            HamtaFullmakterResponse, "/sok/fullmakter", request, user_token=user_token
        )

    def hamta_fullmakt(
        self,
        tredjeman: str,
        fullmaktsid: Union[str, UUID],
        *,
        user_token: Optional[str] = None,
    ) -> FullmaktMetadataResponse:

        response = self._get(
            FullmaktMetadataResponse,
            f"/tredjeman/{tredjeman}/fullmakter/{fullmaktsid}",
            user_token=user_token,
        )
        if not verify_embedded_jws(response, self.get_jwk_set(tredjeman)):
            raise ValueError(f"Ogiltig signatur för fullmakt {tredjeman} {fullmaktsid}")
        return response
