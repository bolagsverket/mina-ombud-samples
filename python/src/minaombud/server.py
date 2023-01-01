import base64
import cgi
import dataclasses
import html
import json
import logging
import re
import time
from dataclasses import dataclass
from http import HTTPStatus
from typing import (
    Optional,
    Collection,
    Mapping,
    Any,
    Dict,
    Union,
    List,
    Callable,
    Sequence,
)
from wsgiref.simple_server import make_server

from minaombud.crypto import jose
from minaombud.crypto.jwkset import JwkSet
from minaombud.defaults import (
    MINA_OMBUD_SAMPLE_USER_DB,
    MINA_OMBUD_SAMPLE_CLIENT_ID,
    MINA_OMBUD_SAMPLE_CLIENT_SECRET,
    MINA_OMBUD_SAMPLE_ISSUER,
    MINA_OMBUD_SAMPLE_USER_PASSWORD,
    MINA_OMBUD_SAMPLE_AUDIENCE,
    MINA_OMBUD_SAMPLE_BIND,
    MINA_OMBUD_SAMPLE_PORT,
    MINA_OMBUD_SAMPLE_KEYS,
)
from minaombud.model import Identitetsbeteckning, Identitetstyp
from minaombud.serialization import encode_json
from minaombud.user import (
    auth_user,
    Unauthorized,
    issue_token_response,
    load_user_database,
    create_user_token,
)
from minaombud.util import base64_encode_urlsafe


@dataclass
class Response:
    status: int = 200
    headers: Mapping[str, Union[str, List[str]]] = dataclasses.field(
        default_factory=dict
    )
    body: Optional[Union[str, bytes]] = None

    @staticmethod
    def ok(body: Union[str, bytes], content_type: str) -> "Response":
        headers = {"content-type": content_type}
        return Response(body=body, headers=headers)


def error(code: int, message: Optional[str] = None) -> Response:
    body_format = """\
<!DOCTYPE html>
<html>
    <head>
        <meta charset="utf-8">
        <title>Error</title>
    </head>
    <body>
        <h1>Error</h1>
        <p>Error code: %(code)d</p>
        <p>Message: %(message)s.</p>
    </body>
</html>"""
    status = HTTPStatus(code)
    if not message:
        message = status.description or status.phrase

    body = (
        body_format
        % {
            "code": int(status),
            "message": html.escape(message, quote=False),
        }
    ).encode("utf-8")

    headers = {
        "content-type": "text/html;charset=utf-8",
    }

    return Response(code, headers=headers, body=body)


def not_found(message: Optional[str] = None) -> Response:
    return error(HTTPStatus.NOT_FOUND, message)


def _first_header(headers: Dict[str, List[str]], name: str) -> Optional[str]:
    lst = headers.get(name)
    return lst[0] if lst else None


def _read_request_body(environ: Dict[str, Any]) -> Optional[bytes]:
    content_length = environ.get("CONTENT_LENGTH")
    if not content_length:
        return None
    content_length = int(content_length)
    if not content_length:
        return None
    f = environ["wsgi.input"]
    return f.read(content_length)


class PathHandler:
    path = "/"
    methods = ["GET"]

    def handle(
        self, headers: Dict[str, List[str]], environ: Dict[str, Any]
    ) -> Optional[Response]:
        raise NotImplementedError()


class PathWSGIApp:
    """Simple WSGI app that dispatches based on path.

    Invokes a :class:`PathHandler` if it has a matching path prefix.

    Handlers are tried in registration order.

    Only meant for testing, not any serious use.

    Args:
        paths:      Callbacks for paths.
        context:    Base path for all requests.
    """

    def __init__(self, paths: Collection[PathHandler], context="/"):
        self.context = context.rstrip("/")
        self.paths = paths

    def __call__(self, environ: Dict[str, Any], start_response: Callable):
        path: str = environ["PATH_INFO"].rstrip("/")
        method: str = environ["REQUEST_METHOD"]
        headers: Dict[str, List[str]] = {}
        for k, v in environ.items():
            if k.startswith("HTTP_"):
                hdr = k[5:].replace("_", "-").lower()
                if hdr in headers:
                    headers[hdr].append(v)
                else:
                    headers[hdr] = [v]

        content_length = environ.get("CONTENT_LENGTH")
        if content_length:
            headers["content-length"] = [content_length]

        content_type = environ.get("CONTENT_TYPE")
        if content_type:
            headers["content-type"] = [content_type]

        response = None
        if path.startswith(f"{self.context}/") or path == self.context:
            path = path[len(self.context) :] or "/"
            for handler in self.paths:
                if method in handler.methods and handler.path.startswith(path):
                    response = handler.handle(headers, environ)
                    break

        if response is None:
            response = not_found()

        response_headers = []
        if response.headers:
            for k, v in response.headers.items():
                if isinstance(v, str):
                    response_headers.append((k, v))
                else:
                    response_headers.extend((k, e) for e in v)

        body = response.body
        if "content-length" not in response.headers and body is not None:
            if isinstance(body, str):
                body = body.encode("utf-8")

        status = HTTPStatus(response.status)
        start_response(f"{status.value} {status.phrase}", response_headers)
        return [] if body is None else [body]


class JwksRequestHandler(PathHandler):
    """JSON Web Key Set request handler."""

    path = "/"

    def __init__(self, jwks: JwkSet, private_keys=False):
        """
        Args:
            jwks: keys to serve.
            private_keys: If True, all keys are served rather than only public keys.
        """
        self.jwks = jwks
        self.private_keys = private_keys
        super(JwksRequestHandler, self).__init__()

    def handle(
        self, headers: Dict[str, List[str]], environ: Dict[str, Any]
    ) -> Optional[Response]:
        keys = list(self.jwks.all_keys if self.private_keys else self.jwks.public_keys)
        response = json.dumps(encode_json({"keys": keys}), indent=2).encode("utf-8")
        return Response.ok(response, "application/jwk-set+json")


class SigningHandler(PathHandler):
    path = "/sign"
    methods = ["POST"]

    def __init__(self, jwks: JwkSet):
        self.jwks = jwks

    def handle(
        self, headers: Dict[str, List[str]], environ: Dict[str, Any]
    ) -> Optional[Response]:
        content_type = _first_header(headers, "content-type")
        if content_type:
            content_type, params = cgi.parse_header(content_type)
            content_type = content_type.lower()

        request_body = _read_request_body(environ)
        if not request_body:
            return error(HTTPStatus.BAD_REQUEST)

        if content_type == "text/plain":
            payload = request_body
        else:
            payload = base64_encode_urlsafe(request_body)

        jws = jose.sign_bytes(payload, self.jwks)
        return Response.ok(jws, "application/jose")


@dataclass
class AuthConfig:
    users: Mapping[str, Mapping[str, Any]]
    default_user: Optional[Mapping[str, Any]] = None
    issuer: Optional[str] = None
    audience: Optional[Sequence[str]] = None
    typ = "ID"
    expiry_time: int = 0
    default_password: str = ""
    client_id: Optional[str] = None
    client_secret: Optional[str] = None


class OAuth2TokenHandler(PathHandler):
    path = "/oauth2/token"
    methods = ["POST"]

    def __init__(self, jwks: JwkSet, config: AuthConfig):
        self.jwks = jwks
        self.config = config

    def handle(
        self, headers: Dict[str, List[str]], environ: Dict[str, Any]
    ) -> Optional[Response]:
        content_type = _first_header(headers, "content-type")
        content_type, params = (
            cgi.parse_header(content_type) if content_type else ("", {})
        )

        if content_type.lower() != "application/x-www-form-urlencoded":
            return error(HTTPStatus.NOT_ACCEPTABLE)

        form = cgi.parse(environ["wsgi.input"], environ, keep_blank_values=True)
        scope_param = form.get("scope", [""])[0]
        scope = list(scope_param.split(" ")) if scope_param else []

        client_id: str
        client_secret: str
        claims: Dict[str, Any]
        typ = self.config.typ
        issuer = self.config.issuer
        audience = self.config.audience
        try:
            if auth := _first_header(headers, "authorization"):
                if not auth.startswith("Basic "):
                    raise Unauthorized()
                if any(p in form for p in ("client_id", "client_secret")):
                    return error(HTTPStatus.BAD_REQUEST)
                client_id, client_secret = (
                    base64.standard_b64decode(auth[7:]).decode("utf-8").split(":", 1)
                )
            else:
                client_id, client_secret = (
                    form["client_id"][0],
                    form["client_secret"][0],
                )

            if self.config.client_id and (client_id != self.config.client_id):
                raise Unauthorized()
            if self.config.client_secret and (
                client_secret != self.config.client_secret
            ):
                raise Unauthorized()

            grant_type = form["grant_type"][0]
            if grant_type == "password":
                username, password = form["username"][0], form["password"][0]
                claims = auth_user(
                    username,
                    password if password else None,
                    scope=scope,
                    users=self.config.users,
                    issuer=self.config.issuer,
                    audience=audience,
                    client_id=client_id,
                    typ=typ,
                    expiry_time=self.config.expiry_time,
                    default_user=self.config.default_user,
                    default_password=self.config.default_password,
                )

            elif grant_type == "client_credentials":
                iat = int(time.time())
                typ = "Bearer"
                claims = {
                    "sub": f"client:{client_id}",
                    "typ": typ,
                    "scope": scope_param,
                    "iat": iat,
                }
                if self.config.expiry_time:
                    claims["exp"] = iat + self.config.expiry_time
                if issuer:
                    claims["iss"] = issuer
                if audience:
                    if len(audience) > 1:
                        claims["aud"] = audience
                        claims["azp"] = client_id
                    else:
                        claims["aud"] = audience[0]
            else:
                raise Unauthorized()
        except Unauthorized:
            return error(HTTPStatus.UNAUTHORIZED)
        except LookupError:
            return error(HTTPStatus.BAD_REQUEST)

        token_response = issue_token_response(
            claims, self.jwks, typ=typ, scope=scope, expiry_time=self.config.expiry_time
        )
        response = json.dumps(token_response, indent=2).encode("utf-8")
        return Response.ok(response, "application/json")


class UserTokenHandler(PathHandler):
    path = "/user"
    methods = ["POST"]

    def __init__(self, jwks: JwkSet, config: AuthConfig):
        self.jwks = jwks
        self.config = config

    def handle(
        self, headers: Dict[str, List[str]], environ: Dict[str, Any]
    ) -> Optional[Response]:
        content_type = _first_header(headers, "content-type")
        if content_type:
            content_type, params = cgi.parse_header(content_type)
        else:
            content_type, params = "application/octet-stream", {}
        content_type = content_type.lower()
        charset = params.get("charset")
        if not charset:
            charset = "latin-1" if content_type.startswith("text/") else "utf-8"

        try:
            if content_type in (
                "text/csv",
                "text/plain",
                "application/json",
                "application/octet-stream",
            ):
                request_body = _read_request_body(environ)
                if not request_body:
                    return error(HTTPStatus.BAD_REQUEST)

                token = create_user_token(
                    request_body.decode(charset),
                    self.jwks,
                    users=self.config.users,
                    issuer=self.config.issuer,
                    audience=self.config.audience,
                    client_id=self.config.client_id,
                    expiry_time=self.config.expiry_time,
                )
            elif content_type == "application/x-www-form-urlencoded":
                form = cgi.parse(environ["wsgi.input"], environ)
                claims = {k: l[0] for k, l in form.items()}
                username = claims.pop("username", claims.pop("user", None))
                password = claims.pop("password", self.config.default_password)
                client_id = claims.pop("client_id", self.config.client_id)
                if username:
                    if re.match(r"^(19|20)\d{6}-?\d{4}$", username):
                        identitet = Identitetsbeteckning.from_id(
                            username.replace("-", "")
                        )
                        if identitet.typ == Identitetstyp.PNR:
                            claims[
                                "https://claims.oidc.se/1.0/personalNumber"
                            ] = identitet.id
                        elif identitet.typ == Identitetstyp.SAMNR:
                            claims[
                                "https://claims.oidc.se/1.0/coordinationNumber"
                            ] = identitet.id
                        else:
                            claims["sub"] = f"{identitet.typ}:{identitet.id}"

                    claims = auth_user(
                        username,
                        password,
                        self.config.users,
                        audience=self.config.audience,
                        issuer=self.config.issuer,
                        typ=self.config.typ,
                        expiry_time=self.config.expiry_time,
                        default_user=claims,
                        default_password=self.config.default_password,
                        client_id=client_id,
                    )
                token = jose.sign(claims, self.jwks)
            else:
                return error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
        except Unauthorized:
            return error(HTTPStatus.UNAUTHORIZED)

        return Response.ok(token, "application/jose")


try:
    from waitress import serve as serve
    from paste.translogger import TransLogger

    def serve_app(app, host: str, port: int):
        logger = logging.getLogger("waitress")
        logger.setLevel(logging.INFO)
        app = TransLogger(app, setup_console_handler=False)
        serve(app, host=host, port=port)

except ImportError:

    def serve_app(app, host: str, port: int):
        with make_server(host, port, app) as httpd:
            sa = httpd.socket.getsockname()
            print("Listening on ", sa[0], "port", sa[1], "...")
            try:
                httpd.serve_forever()
            except KeyboardInterrupt:
                pass


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("keys", nargs="*", metavar="KEY")
    parser.add_argument(
        "--host",
        "-b",
        metavar="ADDRESS",
        default=MINA_OMBUD_SAMPLE_BIND,
        help="Specify alternate bind address",
    )
    parser.add_argument(
        "--port",
        "-p",
        default=MINA_OMBUD_SAMPLE_PORT,
        type=int,
        help="Specify alternate port",
    )

    parser.add_argument("--context", default="/", help="Base path for server.")

    parser.add_argument(
        "--private-keys",
        default=False,
        action="store_true",
        help="Publish private keys.",
    )
    parser.add_argument(
        "--signing", default=False, action="store_true", help="Enable signing endpoint."
    )

    parser.add_argument(
        "--auth",
        default=False,
        action="store_true",
        help="Enable auth endpoints (/oauth2/token, /user).",
    )
    parser.add_argument(
        "--client-id",
        default=MINA_OMBUD_SAMPLE_CLIENT_ID,
        help="Client ID for auth requests.",
    )
    parser.add_argument(
        "--client-secret",
        default=MINA_OMBUD_SAMPLE_CLIENT_SECRET,
        help="Client secret for auth requests.",
    )
    parser.add_argument(
        "--user-db",
        metavar="FILE",
        default=MINA_OMBUD_SAMPLE_USER_DB,
        help="Load users from file.",
    )
    parser.add_argument(
        "--user-password",
        "--user-pass",
        default=MINA_OMBUD_SAMPLE_USER_PASSWORD,
        help="Default user password for auth requests.",
    )
    parser.add_argument(
        "--issuer",
        "--iss",
        default=MINA_OMBUD_SAMPLE_ISSUER,
        help="Issuer for signed JWT:s.",
    )
    parser.add_argument(
        "--audience", "--aud", action="append", help="Value(s) for JWT aud claim."
    )
    parser.add_argument(
        "--expiry-time",
        "--expiry",
        "--exp",
        default=120,
        type=int,
        help="Expiry time for signed JWT:s.",
    )

    args = parser.parse_args()
    if not args.audience:
        args.audience = MINA_OMBUD_SAMPLE_AUDIENCE

    if not args.keys:
        args.keys = MINA_OMBUD_SAMPLE_KEYS
        if not args.keys:
            parser.error("No keys specified")

    jwks = JwkSet.load(args.keys)
    if not jwks:
        parser.exit(1, f"No keys found in {args.keys}")

    paths = [JwksRequestHandler(jwks, args.private_keys)]
    if args.signing:
        signer = SigningHandler(jwks)
        paths.append(signer)

    if args.user_db:
        with open(args.user_db, "rb") as f:
            users = load_user_database(f)
    else:
        users = {}

    if args.auth or users:
        config = AuthConfig(
            users=users,
            issuer=args.issuer,
            audience=args.audience,
            client_id=args.client_id,
            client_secret=args.client_secret,
            expiry_time=args.expiry_time,
            default_password=args.user_password,
        )
        paths.extend([OAuth2TokenHandler(jwks, config), UserTokenHandler(jwks, config)])

    app = PathWSGIApp(paths, args.context)
    serve_app(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
