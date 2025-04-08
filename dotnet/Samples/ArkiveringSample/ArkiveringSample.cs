using System.Globalization;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System;
using System.IO;
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
// 1. Request API access token.
// The access token should be requested and reused for subsequent requests
// until it expires at which point a new token must be requested.

var tokenRequest = new FormUrlEncodedContent(new Dictionary<string, string>
    {
        { "grant_type", "client_credentials" },
        { "client_id", defaults.MINA_OMBUD_API_CLIENT_ID },
        { "client_secret", defaults.MINA_OMBUD_API_CLIENT_SECRET },
        { "scope", "fullmakt:arkivering" }
    }
);

var tokenResponse = await Post<Dictionary<string, object>>(authUrl, tokenRequest);
var accessToken = tokenResponse["access_token"].ToString();
authenticatedClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {accessToken}");
authenticatedClient.DefaultRequestHeaders.Add("x-service-name", "ArkiveringSample.cs");
authenticatedClient.DefaultRequestHeaders.Add("x-request-id", Guid.NewGuid().ToString());

///////////////////////////////////////////////////////////////////////////////
// 2. Invoke API
var Tredjeman = defaults.MINA_OMBUD_TREDJE_MAN;
var PaketUrl = $"{apiUrl}/tredjeman/{Tredjeman}/arkivering/paket";
var response = await ApiGet<ArkiveringsinformationResponse>(PaketUrl);
Console.WriteLine(PrettyPrint(response));

var OutputDir = "archive";

foreach (var pkg in response.Paket)
{
    var id = pkg.Id;
    var ZipName = $"{id}.zip";
    var ZipDir = Path.Join(OutputDir, pkg.Namn);
    var ZipPath = Path.Join(ZipDir, ZipName);
    var ZipData = await GetBytes($"{PaketUrl}/{id}");
    Directory.CreateDirectory(ZipDir);
    File.WriteAllBytes(ZipPath, ZipData);
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

async Task<T> ApiGet<T>(string uri)
{
    var r = await authenticatedClient.GetAsync(uri);
    r.EnsureSuccessStatusCode();
    var body = await r.Content.ReadFromJsonAsync<T>(serializeOptions);
    if (body == null)
    {
        throw new InvalidDataException($"No response body returned from {uri}");
    }

    return body;
}

async Task<byte[]> GetBytes(string uri)
{
    var r = await authenticatedClient.GetAsync(uri);
    r.EnsureSuccessStatusCode();
    var body = await r.Content.ReadAsByteArrayAsync();
    if (body == null)
    {
        throw new InvalidDataException($"No response body returned from {uri}");
    }

    return body;
}
