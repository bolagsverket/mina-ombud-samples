package se.minaombud.client;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import se.minaombud.crypto.KeyList;
import se.minaombud.json.Json;
import se.minaombud.model.HamtaBehorigheterRequest;
import se.minaombud.model.HamtaFullmakterRequest;
import se.minaombud.model.Identitetsbeteckning;

import java.net.URI;
import java.net.http.HttpClient;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThatNoException;

class ApiClientTestIT {

    static final String MINA_OMBUD_API_CLIENT_ID = getConfig("MINA_OMBUD_API_CLIENT_ID", "mina-ombud-sample");

    static final String MINA_OMBUD_API_CLIENT_SECRET =
        getConfig("MINA_OMBUD_API_CLIENT_SECRET", "3392d044-d0f2-491d-a40d-edda4f1361c0");

    static final URI MINA_OMBUD_API_TOKEN_URL = URI.create(getConfig("MINA_OMBUD_API_TOKEN_URL",
        "https://auth-accept.minaombud.se/auth/realms/dfm/protocol/openid-connect/token"));

    static final URI MINA_OMBUD_API_URL =
        URI.create(getConfig("MINA_OMBUD_API_URL", "https://fullmakt-test.minaombud.se/dfm/formedlare/v1"));

    static final String MINA_OMBUD_SAMPLE_SERVICE = getConfig("MINA_OMBUD_SAMPLE_SERVICE", "ApiClientTestIT.java");
    static final String MINA_OMBUD_SAMPLE_ISSUER = getConfig("MINA_OMBUD_SAMPLE_ISSUER", "http://localhost");

    static final List<String> MINA_OMBUD_SAMPLE_AUDIENCE;

    static {
        var aud = getConfig("MINA_OMBUD_SAMPLE_AUDIENCE", "mina-ombud");
        MINA_OMBUD_SAMPLE_AUDIENCE = Stream.of(aud.split(","))
            .filter(s -> !s.isBlank())
            .collect(Collectors.toList());
    }

    static final KeyList keys = TestUtil.loadTestKeys();

    static final Json json = new Json();

    static String ssn = "198602262381";

    static Map<String, Object> userClaims = Map.of(
        "sub", "9ebe70e4-ca61-11ed-97ed-00155d52ccdb",
        "name", "Beri Ylles",
        "given_name", "Beri",
        "family_name", "Ylles",
        "https://claims.oidc.se/1.0/personalNumber", ssn);

    static ApiClient client;

    @BeforeAll
    static void setupClass() {
        client = new ApiClient(HttpClient.newHttpClient(), json, keys)
            .apiUrl(MINA_OMBUD_API_URL)
            .tokenEndpoint(MINA_OMBUD_API_TOKEN_URL)
            .clientId(MINA_OMBUD_API_CLIENT_ID)
            .clientSecret(MINA_OMBUD_API_CLIENT_SECRET)
            .service(MINA_OMBUD_SAMPLE_SERVICE)
            .issuer(MINA_OMBUD_SAMPLE_ISSUER)
            .audience(MINA_OMBUD_SAMPLE_AUDIENCE);
    }

    static String getConfig(String name, String defaultValue) {
        String val = System.getProperty(name);
        if (val == null) {
            val = System.getenv(name);
        }

        return val != null ? val : defaultValue;
    }

    @Test
    void slutanvandare_kan_soka_fullmakter() {
        var request = new HamtaFullmakterRequest()
            .fullmaktshavare(new Identitetsbeteckning().id(ssn).typ("pnr"));
        assertThatNoException().isThrownBy(() -> client
            .scope("user:self")
            .request()
            .userClaims(userClaims)
            .sokFullmakter(request));
    }

    @Test
    void system_kan_soka_fullmakter() {
        var request = new HamtaFullmakterRequest()
            .fullmaktsgivare(new Identitetsbeteckning().id("5561929323").typ("orgnr"));
        assertThatNoException().isThrownBy(() -> client
            .scope("user:any")
            .request()
            .sokFullmakter(request));
    }

    @Test
    void slutanvandare_kan_soka_behorigheter() {
        var request = new HamtaBehorigheterRequest()
            .tredjeman("2120000829")
            .fullmaktshavare(new Identitetsbeteckning().id(ssn).typ("pnr"));
        assertThatNoException().isThrownBy(() -> client
            .scope("user:self")
            .request()
            .userClaims(userClaims)
            .sokBehorigheter(request));
    }

    @Test
    void system_kan_soka_behorigheter() {
        var request = new HamtaBehorigheterRequest()
            .tredjeman("2120000829")
            .fullmaktsgivare(new Identitetsbeteckning().id("5561929323").typ("orgnr"))
            .fullmaktshavare(new Identitetsbeteckning().id(ssn).typ("pnr"));
        assertThatNoException().isThrownBy(() -> client
            .scope("user:any")
            .request()
            .sokBehorigheter(request));
    }

}
