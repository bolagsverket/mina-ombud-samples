# Mina ombud - exempel

Exempelkod som kan användas för att testa mot Mina ombuds testmiljö.

Exempel finns för
- [C#/.NET](dotnet)
- [Java](java)
- [PowerShell](powershell)
- [Python](python)

## Att anropa API:er

För att anropa ett API krävs följande:
- Ett namn för anropande tjänst (`X-Service-Name: myservice`).
  Bör vara samma service-namn som i SSBT om SSBT också används. 
  X-Service-Name får bara innehålla tecknen [a-zA-Z0-9._-].
- En access-token för API:et (`Authorization: Bearer <ACCESS_TOKEN>`)
- En signerad id-token (JWS) med information om slutanvändaren
  (`X-Id-Token: <ID_TOKEN>`).
- En webb-server som tillhandahåller den publika nyckeln för 
  att verifiera signatur på ID-token. Nycklarna ska tillhandahållas
  i form av ett JSON Web Key Set. Denna endpoint ska registreras hos
  Mina ombud tillsammans med förväntad issuer (`iss`) och audience (`aud`). 

### 1. Begär access token

Token request
```http request
POST /auth/realms/dfm-accept2/protocol/openid-connect/token HTTP/1.1
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&scope=user:self
```

Token response
```http request
HTTP/1.1 200 OK
Content-Type: application/json

{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "user:self"
}
```

Spara attributet `access_token` och använd som Bearer-token i API-anrop.

Återanvänd samma access token tills den går ut.
Tiden när token går ut kan beräknas från tid för token request och attributet `expires_in`
(som anges i sekunder).

### 2. Skapa ID-token för slutanvändaren

Mina ombud kräver en signerad JWT med information om slutanvändaren (se [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)).

Claims som följer [Swedish OpenID Connect Profile](https://github.com/oidc-sweden/specifications/blob/main/swedish-oidc-claims-specification.md#21-user-identity-claims)
ska användas för att identifiera användaren.

Se [pseudo-kod](#signeringsexempel), [enduser_sample.py](python/src/minaombud/samples/enduser_sample.py)
eller [EndUserSample.cs](dotnet/Samples/EndUserSample/EndUserSample.cs)
för konkreta exempel.

### 3. Anropa API med access och id-token
```http request
POST /dfm/formedlare/v2/sok/behorigheter HTTP/1.1
Authorization: Bearer <access_token>
X-Id-Token: <user_token>
X-Service-Name: myservice
Content-Type: application/json

{
  "tredjeman": "2120000829",
  "fullmaktshavare": {"id": "198602262381", "typ": "pnr"},
  "fullmaktsgivarroll": ["ORGANISATION"],
  "page": {"page": 0, "size": 100}
}
```

### 4. Verifiera digital signatur på svaret

Pseudo-Javascript för att verifiera digital signatur på ett signerat objekt.

```javascript
const behorigheter_response = {
  "kontext": [
    {
      "tredjeman": "2120000829",
      "fullmaktshavare": [ {"id": "198602262381", "typ": "pnr"} ],
      "fullmaktsgivare": { "id": "5564372307", "typ": "orgnr" },
      "fullmaktsgivarroll": "ORGANISATION",
      "behorigheter": [
        { "kod": "ceb9028a-ffce-4b9a-adca-165972fec48a", "typ": "aktiv", "fullmakt": "4988f9a2-542a-4945-ba79-ec151563d8b8" }
      ],
      "_sig": {
        "protected": "...",
        "signature": "..."
      }
    }
  ],
  "page": {
    "size": 100,
    "totalElements": 1,
    "totalPages": 1,
    "number": 0
  }
}

function decode_base64(b64) {
  return decodeURIComponent(escape(atob(b64)))
}

const kontext = behorigheter_response.kontext[0]
const { _sig, ...payload } = kontext
const jose_hdr = JSON.parse(decode_base64(_sig.protected))
const valid_hdr = (
  typeof jose_hdr.kid === 'string' &&
  (typeof jose_hdr.typ === 'undefined' || jose_hdr.typ === 'JWT') &&
  ["RS256", "RS384", "RS512"].includes(jose_hdr.alg)
)
// Hämta key set för tredje man
const tredjeman = payload.tredjeman
const { keys } = await fetch(`${api_url}/tredjeman/${tredjeman}/jwks`)
    .then(response => response.json())
const public_key = keys.find(k => k.kid === jose_hdr.kid)
const valid_key = (
    public_key?.kty === "RSA" &&
    (typeof public_key.use === 'undefined' || public_key.use === 'sig') &&
    (!public_key.key_ops?.length || public_key.key_ops.includes('verify'))
)
  
// Normalisera JSON: https://www.rfc-editor.org/rfc/rfc8785
const canonical_payload = canonical_json(payload)
// Konstruera det data som signaturen baseras på
const signing_input = _sig.protected + "." + canonical_payload
// Verifiera signaturen med den publika nyckeln
const valid_signature = verify_signature(signing_input, _sig.signature, public_key)
```

## Krav på signering av ID-token för slutanvändare

Mina ombud kräver en signerad JWT med information om slutanvändaren.

Följande krav finns på nycklar för verifiering av signaturer
- En RSA-nyckel med en minsta längd på 2048 bitar ska användas.
- Den publika nyckeln ska publiceras som ett JSON Web Key Set
  åtkomligt för Mina ombud. [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517#section-5).
- Attributet `kty` ska ha värdet `RSA` vilket indikerar en RSA-nyckel.
- Attributet `alg` ska OM det anges vara `RS256`, `RS384` eller `RS512` enligt
  [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518#section-3.1).
- Attributet `use` ska ha värdet `sig` eller utelämnas.
- Attributet `key_ops` bör utelämnas men om det anges ska det innehålla värdet `verify`.
- Om JSON Web Key Set innehåller ett certifikat så ska även `x5t#S256` anges.
- Nycklar ska identifieras med Key ID (attributet `kid`) som t.ex.
  kan sättas till samma värde som `x5t#S256` (SHA-256 fingerprint av certifikatet),
  SHA-256 av den publika nyckeln (modulus och exponent), ett UUID eller
  annan unik identifierare för den anslutande parten.
- Samma nyckel får inte användas i både produktion och test.

Följande krav finns på den JWS som innehåller användarinformation 
- Signeringsalgoritmen (`alg`) ska anges i JWS protected header
  och vara `RS256`, `RS384` eller `RS512` enligt
  [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518#section-3.1).
- Attributet `kid` ska anges i JWS protected header och indikera
  vilken nyckel som används för att verifiera signaturen.
- Attributet `typ` i JWS protected header ska utelämnas eller
  sättas till värdet `JWT`. 
- Attributet `iss` ska registreras i Mina ombud admin för att verifieras.
- Om attributet `aud` används så ska accepterade värden registreras
  i Mina ombud admin för att kunna verifieras.
- Claims ska ha separata issuer (`iss`) och audience (`aud`)
  om någon typ av testautentisering används (t.ex. BankID för test)
  jämfört med värden för skarp autentisering. Detta för att mimimera
  konsekvenser av felkonfigurerade miljöer.
- Attributet `azp` ska finnas och matcha ett av elementen i `aud`
  om `aud` är en lista med flera värden.
- Attributen `iat` och `exp` bör anges för att begränsa informationens
  livslängd och hur länge en exponerad token kan brukas.
- Attributet `https://id.oidc.se/claim/personalIdentityNumber` ska sättas
  till personnummer vid identifiering av part i fullmakt.
- Attributet `https://id.oidc.se/claim/coordinationNumber` ska sättas
  till samordningsnummer vid identifiering av part i fullmakt.
- Attributet `preferred_username` ska sättas för användare
  som inte identifieras med person- eller samordningsnummer
  och inte är part i fullmakten (t.ex. personer som representerar
  tredje man).
- Attributet `sub` ska finnas.

Om ett autentiseringssystem redan finns som använder
OpenID Connect och följer [Swedish OpenID Connect Profile](https://github.com/oidc-sweden/specifications/blob/main/swedish-oidc-claims-specification.md#21-user-identity-claims)
så kan ID-token användas direkt med Mina ombud förutsatt att den publika
nyckeln för att verifiera signaturen är tillgänglig för Mina ombud.

Tidigare utkast av specifikationen accepteras också tillsvidare (t.ex. `https://claims.oidc.se/1.0/personalNumber`).

### Signeringsexempel 
För att signera informationen rekommenderas ett beprövat bibliotek
för token-signering. En förteckning finns på https://jwt.io/libraries.

Pseudo-Javascript för att konstruera en JWS enligt [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515).

```javascript
function btoa_urlsafe(s) {
  // Koda som Base64 och översätt till URL-safe Base64 utan padding 
  return (btoa(s)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, ''))
}

function encode_utf8_urlsafe_base64(str) {
  // Procentkoda UTF 8-representationen av strängen
  const percent = encodeURIComponent(str)
  // Avkoda procentkodningen för att få en byte-sträng
  const unescaped = unescape(percent)
  // Koda som Base64
  return btoa_urlsafe(unescaped)
}

function encode_json_urlsafe_base64(value) {
  // Konstruera JSON-sträng och koda UTF 8-representationen
  // som URL-safe Base64.
  return encode_utf8_urlsafe_base64(JSON.stringify(value))
}

function sign_claims(claims, jwk) {
  const jose_header = {
    "alg": "RS256",
    "kid": jwk.kid
  }
  const signing_input = encode_json_urlsafe_base64(jose_header) +
    "." + encode_json_urlsafe_base64(claims)
  // Signera med RS256
  const signature = rs256(signing_input, jwk)
  return signing_input + "." + btoa_urlsafe(signature)
}

function get_signing_key() {
  // Privat nyckel för signering
  return {
    "kty": "RSA",
    "kid": "3LD-ss8BVk7TDj3c4rWmRV74tlD8LlWTiZfLDPUpLrA",
    "use": "sig",
    "alg": "RS256",
    "n": "...",
    "e": "...",
    "d": "...",
    "x5c": [
      "..."
    ],
    "x5t#S256": "..."
  }
}
const jwk = get_signing_key()
const user_token = sign_claims({
  "https://id.oidc.se/claim/personalIdentityNumber": "198602262381",
  "name": "Beri Ylles",
  "given_name": "Beri",
  "family_name": "Ylles",
  "iat": 1669031653,
  "exp": 1669031953,
  "iss": "https://auth.example.com/test",
  "aud": "mina-ombud",
  "sub": "9ebe70e4-ca61-11ed-97ed-00155d52ccdb"
}, jwk)
```
