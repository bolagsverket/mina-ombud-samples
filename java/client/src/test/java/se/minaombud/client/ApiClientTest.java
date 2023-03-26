package se.minaombud.client;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import se.minaombud.crypto.KeyList;
import se.minaombud.crypto.SignatureVerificationException;
import se.minaombud.json.Json;
import se.minaombud.model.ApiError;
import se.minaombud.model.ApiErrorCode;
import se.minaombud.model.ApiErrorType;
import se.minaombud.model.Behorighetskontext;
import se.minaombud.model.Fullmaktsgivare;
import se.minaombud.model.Fullmaktshavare;
import se.minaombud.model.HamtaBehorigheterRequest;
import se.minaombud.model.HamtaBehorigheterResponse;
import se.minaombud.model.UtdeladBehorighet;

import java.io.IOException;
import java.net.URI;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletionException;

import static org.assertj.core.api.Assertions.*;

class ApiClientTest {

    static KeyList keys = TestUtil.loadTestKeys();

    static Json json = new Json();

    MockWebServer server;
    ApiClient client;

    @BeforeEach
    void setup() throws IOException {
        server = new MockWebServer();

        var tokenResponse = new TokenResponse();
        tokenResponse.setAccessToken("token");
        tokenResponse.setExpiresIn(300);
        tokenResponse.setScope("user:self");
        server.enqueue(new MockResponse()
            .addHeader("content-type", "application/json")
            .setBody(json.toString(tokenResponse)));
        server.start();

        client = new ApiClient(keys)
            .apiUrl(server.url("/dfm/formedlare/v1").uri())
            .tokenEndpoint(server.url("/token").uri())
            .clientId("client")
            .clientSecret("secret")
            .scope("user:self");
    }

    @AfterEach
    void teardown() throws IOException {
        server.shutdown();
    }

    @Test
    void testValidSignature() {
        Fullmaktsgivare fullmaktsgivare = fullmaktsgivare();
        Fullmaktshavare fullmaktshavare = fullmaktshavare();
        Behorighetskontext kontext = behorighetskontext(fullmaktsgivare, fullmaktshavare);
        client.signer.signObject(kontext, Behorighetskontext::sig);

        var response = new HamtaBehorigheterResponse()
            .kontext(List.of(kontext));

        server.enqueue(new MockResponse()
            .setHeader("content-type", "application/json")
            .setBody(json.toString(response)));
        server.enqueue(new MockResponse()
            .setHeader("content-type", "application/json")
            .setBody(keys.getActiveJWKSet().toString(true)));

        assertThatNoException()
            .isThrownBy(() -> client.request()
                .sokBehorigheter(new HamtaBehorigheterRequest()));
    }

    @Test
    void testInvalidSignature() {
        Fullmaktsgivare fullmaktsgivare = fullmaktsgivare();
        Fullmaktshavare fullmaktshavare = fullmaktshavare();
        Behorighetskontext kontext = behorighetskontext(fullmaktsgivare, fullmaktshavare);
        client.signer.signObject(kontext, Behorighetskontext::sig);
        kontext.getFullmaktsgivare().fornamn("BAD");

        var response = new HamtaBehorigheterResponse()
            .kontext(List.of(kontext));

        server.enqueue(new MockResponse()
            .setHeader("content-type", "application/json")
            .setBody(json.toString(response)));
        server.enqueue(new MockResponse()
            .setHeader("content-type", "application/json")
            .setBody(keys.getActiveJWKSet().toString(true)));

        assertThatExceptionOfType(SignatureVerificationException.class)
            .isThrownBy(() -> client.request()
                .sokBehorigheter(new HamtaBehorigheterRequest()));
    }
    @Test
    void testSyncError() {
        var error = error();
        server.enqueue(new MockResponse()
            .setResponseCode(500)
            .setHeader("content-type", "application/json")
            .setBody(json.toString(error)));

        assertThatExceptionOfType(ApiException.class)
            .isThrownBy(() -> client.request()
                .hamtaFullmakt("999999999", UUID.fromString("f558fdb6-28c2-478e-9f9f-131b0fc9ec46")))
            .satisfies(ex -> assertThat(ex.getError())
                .isEqualTo(error));
    }

    @Test
    void testAsyncError() {
        var error = error();
        server.enqueue(new MockResponse()
            .setResponseCode(500)
            .setHeader("content-type", "application/json")
            .setBody(json.toString(error)));

        var future = client.request()
            .hamtaFullmaktAsync("999999999", UUID.fromString("f558fdb6-28c2-478e-9f9f-131b0fc9ec46"));

        assertThatExceptionOfType(CompletionException.class)
            .isThrownBy(future::join)
            .withCauseExactlyInstanceOf(ApiException.class)
            .satisfies(ex -> assertThat(((ApiException) ex.getCause()).getError())
                .isEqualTo(error));
    }

    private static ApiError error() {
        return new ApiError()
            .type(URI.create(ApiErrorType.BASIC.getValue()))
            .instance(URI.create(ApiErrorCode.SERVER_ERROR.getValue()))
            .timestamp(OffsetDateTime.now(ZoneOffset.UTC))
            .status(500)
            .title("Internal Server Error")
            .detail("The foo frobbed to quux")
            .requestId("42aa9cd1-3489-4897-81c6-4dfff99c93d3");
    }

    private static Behorighetskontext behorighetskontext(Fullmaktsgivare fullmaktsgivare, Fullmaktshavare fullmaktshavare) {
        return new Behorighetskontext()
            .tredjeman("0000000000")
            .fullmaktsgivare(fullmaktsgivare)
            .fullmaktshavare(List.of(fullmaktshavare))
            .behorigheter(List.of(new UtdeladBehorighet()
                .kod("x")
                .typ("aktiv")
                .fullmakt(UUID.fromString("f558fdb6-28c2-478e-9f9f-131b0fc9ec46"))));
    }

    private static Fullmaktshavare fullmaktshavare() {
        var fullmaktshavare = new Fullmaktshavare();
        fullmaktshavare
            .fornamn("Petronella")
            .namn("Malteskog")
            .id("198602102389")
            .typ("pnr");
        return fullmaktshavare;
    }

    private static Fullmaktsgivare fullmaktsgivare() {
        var fullmaktsgivare = new Fullmaktsgivare();
        fullmaktsgivare
            .namn("TB Bokföringsbyrå AB")
            .id("5561929323")
            .typ("orgnr");
        return fullmaktsgivare;
    }

}
