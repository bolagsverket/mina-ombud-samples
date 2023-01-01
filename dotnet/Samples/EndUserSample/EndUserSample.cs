using System.Globalization;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Jose;
using MinaOmbud;
using MinaOmbud.Models;

var defaults = Defaults.Instance;
var authUrl = defaults.MINA_OMBUD_API_TOKEN_URL;
var apiUrl = defaults.MINA_OMBUD_API_URL;
var serializeOptions = JsonCanonicalizer.SerializerOptions;
var acceptableKeyTypes = new HashSet<string> { Jwk.KeyTypes.RSA };
var acceptableCryptos = new HashSet<string> { "RS256", "RS384", "RS512" };
var unauthenticatedClient = new HttpClient();
var authenticatedClient = new HttpClient();
authenticatedClient.Timeout = Timeout.InfiniteTimeSpan;

///////////////////////////////////////////////////////////////////////////////
// 1. User claims
// These are the values identifying the user.

// Issue and expiry times (2 minutes)
var iat = DateTimeOffset.Now.ToUnixTimeSeconds();
var exp = iat + 60 * 2;

const string ssn = "198602262381"; // Social security number
var userClaims = new Dictionary<string, object>
{
    { "https://claims.oidc.se/1.0/personalNumber", ssn },
    { "name", "Beri Ylles" },
    { "given_name", "Beri" },
    { "family_name", "Ylles" },
    { "iat", iat },
    { "exp", exp },
    { "iss", "http://localhost" },
    { "aud", "mina-ombud" },
};

///////////////////////////////////////////////////////////////////////////////
// 2. Sign user claims
///////////////////////////////////////////////////////////////////////////////

// a) Load signing key
var p12 = new X509Certificate2(Path.Join(defaults.MINA_OMBUD_SAMPLE_DATA, "keys/signing.p12"), "",
    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

// b) Construct a signed token
var userToken = JWT.Encode(userClaims, p12.GetRSAPrivateKey(), JwsAlgorithm.RS256);

///////////////////////////////////////////////////////////////////////////////
// 3. Request API access token.
// The access token should be requested and reused for subsequent requests
// until it expires at which point a new token must be requested.

var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        { "grant_type", "client_credentials" },
        { "client_id", defaults.MINA_OMBUD_API_CLIENT_ID },
        { "client_secret", defaults.MINA_OMBUD_API_CLIENT_SECRET },
        { "scope", "user:self" }
    }
);

var tokenResponse = await Post<Dictionary<string, object>>(authUrl, tokenRequest);
var accessToken = tokenResponse["access_token"].ToString();
authenticatedClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
authenticatedClient.DefaultRequestHeaders.Add("x-id-token", userToken);
authenticatedClient.DefaultRequestHeaders.Add("x-service-name", "EndUserSample.cs");
authenticatedClient.DefaultRequestHeaders.Add("x-request-id", Guid.NewGuid().ToString());

///////////////////////////////////////////////////////////////////////////////
// 4. Invoke API
var request = new HamtaBehorigheterRequest()
{
    Tredjeman = "2120000829", // Where the permission is exercised
    Fullmaktshavare = new Identitetsbeteckning(ssn), // Holder of the permission
    Fullmaktsgivarroll = new List<string> { "ORGANISATION" }, // Filter on issuer type
    Page = new PageParameters(0, 100), // Pagination
    // Request permissions for specific issuer
    // Fullmaktsgivare = new Identitetsbeteckning("556...", "orgnr"),
    // Filter on specific permissions
    // Behorigheter = new List<string> { "5611f2d8-c74e-46e4-aab1-b2f0bd4ce318" }
};

var response = await ApiPost<HamtaBehorigheterResponse>($"{apiUrl}/sok/behorigheter", request);
Console.WriteLine(PrettyPrint(response));

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
foreach (var kontext in response.Kontext)
{
    var givare = kontext.Fullmaktsgivare;
    var havare = kontext.Fullmaktshavare[0];
    Console.WriteLine($"=== fullmaktsgivare={givare.Namn}, fullmaktshavare={havare.Fornamn} {havare.Namn} ===");
    // a) Fetch key set
    //    In a real implementation the keys would be cached
    //    and only fetched when a new key is used.
    var keys = await FetchJwkSet(kontext.Tredjeman);

    // b) Produce the canonical JSON representation of the payload
    //    without the embedded signature.
    var payload = JsonCanonicalizer.Serialize(kontext, detachSig: true);
    Console.WriteLine(payload);

    // c) Encode the JSON string as UTF-8 and convert to Base64 URL without padding
    var b64 = Base64Url.Encode(Encoding.UTF8.GetBytes(payload));

    // d) Construct the JWS
    var jws = kontext.Sig.Protected + "." + b64 + "." + kontext.Sig.Signature;

    // e) Verify header and find the public key to use for verification.
    var headers = JWT.Headers(jws);
    var keyId = (string)headers["kid"];
    var alg = (string)headers["alg"];
    if (!acceptableCryptos.Contains(alg))
    {
        throw new CryptographicException("Unsupported signing algorithm");
    }

    var pubKey = (
        from key in keys
        where key.KeyId == keyId
              && acceptableKeyTypes.Contains(key.Kty)
              && (key.Alg == null || acceptableCryptos.Contains(key.Alg))
        select key
    ).First();

    // f) Verify signature
    JWT.Decode(jws, pubKey);

    // g) Verify timestamp.
    // The tolerance is very application dependent.
    // Here we accept information no older than 2 minutes.
    var timestamp = DateTimeOffset.Parse(kontext.Tidpunkt, CultureInfo.InvariantCulture);
    var delta = DateTimeOffset.Now.Subtract(timestamp);
    if (delta.TotalMinutes > 2)
    {
        Console.WriteLine($"Expired: {timestamp} : {delta}");
    }
}

///////////////////////////////////////////////////////////////////////////////
// Utilities
///////////////////////////////////////////////////////////////////////////////
static string PrettyPrint(object value)
{
    return JsonSerializer.Serialize(value, new JsonSerializerOptions(JsonCanonicalizer.SerializerOptions)
    {
        WriteIndented = true
    });
}

async Task<JwkSet> FetchJwkSet(string tredjeman)
{
    var json = await unauthenticatedClient.GetStringAsync($"{apiUrl}/tredjeman/{tredjeman}/jwks");
    return JwkSet.FromJson(json, JWT.DefaultSettings.JsonMapper);
}

async Task<T> Post<T>(string uri, HttpContent value)
{
    var r = await unauthenticatedClient.PostAsync(uri, value);
    r.EnsureSuccessStatusCode();
    var body = await r.Content.ReadFromJsonAsync<T>(serializeOptions);
    if (body == null)
    {
        throw new InvalidDataException($"No response body returned from {uri}");
    }

    return body;
}

async Task<T> ApiPost<T>(string uri, object value)
{
    var r = await authenticatedClient.PostAsJsonAsync(uri, value, serializeOptions);
    r.EnsureSuccessStatusCode();
    var body = await r.Content.ReadFromJsonAsync<T>(serializeOptions);
    if (body == null)
    {
        throw new InvalidDataException($"No response body returned from {uri}");
    }

    return body;
}
