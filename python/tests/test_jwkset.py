import contextlib
import socket
from threading import Thread
from wsgiref.simple_server import make_server, WSGIRequestHandler

from minaombud.crypto.jwk import Jwk
from minaombud.crypto.jwkset import JwkSet, RemoteJwkSet
from minaombud.crypto.rsa import RSAKey
from minaombud.server import JwksRequestHandler, PathWSGIApp

JWK = Jwk(kty="RSA",
          kid="singing-1",
          e="AQAB",
          n="tCfzfO4-lU1hpHDQunCVm9xQEhQnsO3ZnqTg2NH757pAyEYZY8SVd4pnb7XLXscB8HMwSewqFQY8"
            "kai1sw-l6mXz8jQvMIXi4J9o7flGeDH0t8XzgAS8vqp8XkM6MfMzIVF6Sc_Fwg02hP3Bqjon8TnQ"
            "OAeCuOy8dEESUl1FY-E01T-e6VnxWsWscsQZQ_YiJ8Vt-kym4KZbU4fXe9tjlXTmCEY-N1MslPwV"
            "oCJbUdNoWqN59lnIUqbky0kb_O5S4sToVwRixs4p3Npu-pbJElCLCrlZKRK7NI_9EbXV2AHWjGrW"
            "NI_Ms4LVr9zU1PeebnJIwm8WS0Khn-SusWIrCw")


def test_add_keys():
    repo = JwkSet([JWK])
    assert JWK.kid in repo
    jwk = repo[JWK.kid]
    assert isinstance(jwk, RSAKey)


def local_server_address():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()


class NoLogWSGIRequestHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        pass


@contextlib.contextmanager
def run_wsgi_server(address, app):
    host, port = address
    server = make_server(host, port, app, handler_class=NoLogWSGIRequestHandler)
    thread = Thread(target=server.serve_forever)
    thread.daemon = True
    try:
        thread.start()
        yield server
    finally:
        server.shutdown()


class TestRemoteJwkSet:

    def test(self):
        address = local_server_address()
        app = PathWSGIApp([JwksRequestHandler(JwkSet([JWK]))])
        with run_wsgi_server(address, app):
            host, port = address
            jwk_set = RemoteJwkSet(f"http://{host}:{port}")
            jwk_set.update()
            assert JWK.kid in jwk_set
