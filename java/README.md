# Mina ombud - anslutningsexempel i Java

Kräver Java 11.

Denna kod har beroenden på
- [nimbus-jose-jwt](https://connect2id.com/products/nimbus-jose-jwt) för JOSE/JWS-support.
- [jackson](https://github.com/FasterXML/jackson-databind/) för JSON

Följande exempel finns:
- [model/](model) visar kodgenerering från OpenAPI.
- [client/](client) är en modul med en API-klient och verktyg för att hantera nycklar/certifikat
  och token-signering och -verifiering. 
- [samples/EndUserSample](samples/src/main/java/se/minaombud/samples/EndUserSample.java) visar de steg som
  krävs för att göra API-anrop från början till slut i ett normalfall där
  slutanvändaren är en fullmaktshavare som agerar med en fullmakt.
- [samples/SystemServiceSample](samples/src/main/java/se/minaombud/samples/SystemServiceSample.java) visar stegen
  för att göra anrop som systemtjänst utan slutanvändare.
- [samples/cli/](samples/src/main/java/se/minaombud/samples/cli) är en CLI-applikation
  för att göra testa API-anrop.
