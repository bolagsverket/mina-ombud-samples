# Mina ombud - anslutningsexempel i C#/.NET

Kräver .NET 6.0.

Denna kod är fristående förutom beroenden på
- [jose-jwt](https://www.nuget.org/packages/jose-jwt) för JOSE/JWS-support.

Följande exempel finns:
- [Samples/EndUserSample](Samples/EndUserSample/EndUserSample.cs) visar de steg som
  krävs för att göra API-anrop från början till slut i ett normalfall där
  slutanvändaren är en fullmaktshavare som agerar med en fullmakt

För ett produktionssystem finns bibliotek och ramverk som kan hantera
t.ex. OAuth2 Client Credentials.
