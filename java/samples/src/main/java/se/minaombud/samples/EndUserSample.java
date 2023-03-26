package se.minaombud.samples;

import com.nimbusds.jose.JWSAlgorithm;
import se.minaombud.client.TokenResponse;
import se.minaombud.crypto.JwsSigner;
import se.minaombud.crypto.KeyList;
import se.minaombud.model.FullmaktMetadataResponse;
import se.minaombud.model.FullmaktsgivareRoll;
import se.minaombud.model.HamtaBehorigheterRequest;
import se.minaombud.model.HamtaBehorigheterResponse;
import se.minaombud.model.Identitetsbeteckning;
import se.minaombud.model.PageParameters;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Sample API authenticating with end user.
 *
 * <p>
 * Runs top to bottom illustrating each step:
 * </p>
 * <ol>
 *     <li>Sign user token</li>
 *     <li>Request access token</li>
 *     <li>Invoke API</li>
 *     <li>Verify signatures</li>
 * </ol>
 *
 * <p>
 * Uses {@link java.net.HttpURLConnection} for simplicity.
 * </p>
 */
public class EndUserSample extends SampleBase {

    public static void main(String[] args) throws Exception {
        ///////////////////////////////////////////////////////////////////////////////
        // 1. User claims
        // These are the values identifying the user.

        // Issue and expiry times (2 minutes)
        var iat = Instant.now().getEpochSecond();
        var exp = iat + 60 * 2;

        var ssn = "198602262381"; // Social security number
        var userClaims = Map.of(
            "sub", "9ebe70e4-ca61-11ed-97ed-00155d52ccdb",
            "https://claims.oidc.se/1.0/personalNumber", ssn,
            "name", "Beri Ylles",
            "given_name", "Beri",
            "family_name", "Ylles",
            "iat", iat,
            "exp", exp,
            "iss", "http://localhost",
            "aud", "mina-ombud"
        );

        ///////////////////////////////////////////////////////////////////////////////
        // 2. Sign user claims
        ///////////////////////////////////////////////////////////////////////////////

        // a) Load signing key
        var keys = KeyList.load(Defaults.MINA_OMBUD_SAMPLE_DATA.resolve("keys/signing.p12"), new char[0]);

        // b) Construct a signed token
        var signer = new JwsSigner(keys, JWSAlgorithm.RS256);
        var userToken = signer.signJson(json.toBytes(userClaims)).serialize();

        ///////////////////////////////////////////////////////////////////////////////
        // 3. Request API access token.
        // The access token should be requested and reused for subsequent requests
        // until it expires at which point a new token must be requested.

        var tokenRequestParams = Map.of(
            "grant_type", "client_credentials",
            "client_id", clientId,
            "client_secret", clientSecret,
            "scope", "user:self");
        var tokenRequest = tokenRequestParams.entrySet().stream()
            .map(e -> e.getKey() + '=' + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
            .collect(Collectors.joining("&"));

        var tokenRequestHeaders = Map.of("content-type", "application/x-www-form-urlencoded");
        var tokenResponse = post(TokenResponse.class, authUrl, tokenRequestHeaders, tokenRequest);
        defaultHeaders.put("authorization", "Bearer " + tokenResponse.getAccessToken());
        defaultHeaders.put("x-id-token", userToken);
        defaultHeaders.put("x-service-name", "EndUserSample.java");
        defaultHeaders.put("x-request-id", UUID.randomUUID().toString());

        ///////////////////////////////////////////////////////////////////////////////
        // 4. Invoke API
        var request = new HamtaBehorigheterRequest()
            .tredjeman("2120000829") // Where the permission is exercised
            .fullmaktshavare(new Identitetsbeteckning()
                .id(ssn)
                .typ("pnr"))
            .addFullmaktsgivarrollItem(FullmaktsgivareRoll.ORGANISATION)
            // Request permissions for specific issuer
            // .fullmaktsgivare(new Identitetsbeteckning().id("556...").typ("orgnr"))
            // Filter on specific permissions
            //.addBehorigheterItem("ac94b31e-a17f-11ed-b19d-00155d41fac2")
            // Pagination
            .page(new PageParameters().page(0).size(100));

        var response = post(HamtaBehorigheterResponse.class, apiUrl + "/sok/behorigheter", request);
        System.out.println(json.toPrettyString(response));

        ///////////////////////////////////////////////////////////////////////////////
        // 5. Verify response signature and timestamp
        // When the permissions are passed on to other services/systems
        // instead of being used right away it is important to verify
        // the digital signature of the permissions in the receiving
        // service.
        //
        // This ensures the permissions have not been tampered with.
        //
        // This verification should take place in the receiving service.
        for (var kontext : response.getKontext()) {
            var givare = kontext.getFullmaktsgivare();
            var havare = kontext.getFullmaktshavare().get(0);
            System.out.printf("=== fullmaktsgivare=%s, fullmaktshavare=%s %s ===%n",
                givare.getNamn(), havare.getFornamn(), havare.getNamn());

            var outcome = verifierFactory.forTredjeman(kontext.getTredjeman())
                .verifyDetachedSignature(kontext, kontext.getSig());
            System.out.println(outcome.payload);

            if (!outcome.isVerified()) {
                System.err.println("*INVALID SIGNATURE*");
            }

            // g) Verify timestamp.
            // The tolerance is very application dependent.
            // Here we accept information no older than 2 minutes.
            var timestamp = kontext.getTidpunkt().toInstant();
            var delta = Duration.between(timestamp, Instant.now());
            if (delta.toSeconds() >= 60 * 2) {
                System.err.println("Expired " + kontext.getTidpunkt() + ": " + delta);
            }

            // h) Fetch related documents
            var processedDocuments = new HashSet<UUID>();
            for (var b : kontext.getBehorigheter()) {
                if (!processedDocuments.contains(b.getFullmakt())) {
                    processedDocuments.add(b.getFullmakt());
                    var fullmaktUrl = apiUrl + "/tredjeman/" + kontext.getTredjeman() + "/fullmakter/" + b.getFullmakt();
                    var fullmaktMeta = get(FullmaktMetadataResponse.class, fullmaktUrl);
                    System.out.println(json.toPrettyString(fullmaktMeta));

                    outcome = verifierFactory.forTredjeman(kontext.getTredjeman())
                        .verifyDetachedSignature(fullmaktMeta, fullmaktMeta.getSig());
                    if (!outcome.isVerified()) {
                        System.err.println("*INVALID SIGNATURE*");
                    }
                }
            }
        }
    }

}
