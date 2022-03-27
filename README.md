## Prosjekt i IDATT2104 - Nettverksprogrammering
## Anders Tellefsen, Hasan Omarzae, Brage Minge  

Bruk completed branchen for å kjøre programmet

# OnionChat
OnionChat er en applikasjon som lar en client og en 
server chatte over en sikker forbindelse ved bruk av onion routing.  


### Funksjonalitet på brukernivå
- Dynamisk oppsett av noder, bruker kan selv velge hvor mange noder
det skal være mellom seg selv og mottaker (i dette tilfellet serveren).
- Mulighet for å sende krypterte meldinger fram og tilbake mellom en klient og en "server".

### Funksjonalitet på kodenivå
- Feilfrie oppsettsfunksjoner som oppretter en tilkobling mellom noder, klient og server, ved hjelp av RSA
og AES kryptering. Først ber klient om offentlige nøkkel fra node 1, krypterer deretter node 1 sin symmetriske nøkkel (AES)
med node 1 sin public key (RSA) før den sendes til node 1. Node 1 dekrypterer så dette ved hjelp av sin private nøkkel (RSA)
for å få tak i sin symmetriske nøkkel. Når dette er gjort får klienten en kryptert bekreftelse, og prosessen er klar for å
gjentas til neste node. Node 1 mottar så melding fra klienten om at klienten vil ha offentlig nøkkel fra neste node. Da sender
node 1 meldingen videre, og på vei tilbake krypterer node 1 meldingen fra node x og klienten dekrypterer. 
Rinse and repeat til tilkoblingen er opprettet.
- Logger som hele tiden skriver ut gode meldinger til konsollen i både nodene, klienten og serveren.
- Server oppfører seg som en klient, og sender krypterte meldinger tilbake tilbake til forrige node.
- Klientprogrammet skriver, krypterer, mottar og dekrypterer meldinger til og fra den andre brukeren (serveren) etter at oppsettet er komplett.

### Fremtidig arbeid og svakheter
- Opprette tråder på serverklassen slik at den kan ta imot flere tilkoblinger. Altså istedenfor å bruke serveren som en type klient, så kunne man brukt serveren
som et mellompunkt mellom flere klienter. Slik at flere klinter kan snakke sammen og alle meldingene hadde gått gjennom serveren.
- Tilpasse koden slik at man kan sende HTTPS forespørsler til webtjenere. En måte kunne vært å sette opp en nettleser
til å bruke nodene være som en proxy, slik at all trafikk som nettleseren sender og mottar hadde gått gjennom nodene våre.
- Automatisk opprettelse av noder som kan behandle flere oppsett på en gang, etter brukers ønske.
- Eventuelle svakheter i dependencies er log4j som hadde stor usikkerhet desember 2021, som det ble stor oppmerksomhet rundt.

Alt dette over er noe av det vi kan se for oss å klare å implementere ila en uke der vi alle er friske og ikke har mye annet skole.

### Dependencies
- Log4j til logging

### Installasjonsmanual
Vi bygger prosjektet med intelliJ, men en hvilken som helst annenm IDE skal fungere. Det er derimot
gøyest å kjøre det via cmd som var det bruksområdet vi siktet mot.

HTTPS:
```
git clone https://github.com/bragem/nettverk_prosjekt.git
```

SSH:
```
git clone git@github.com:bragem/nettverk_prosjekt.git
```

### Brukermanual
1. Start det antallet noder du selv vil ha manuelt. For å starte en node på ønsket port, kjører du kommandoen:
```
java OnionNode.java -p <port>
```
Legg deretter inn alle IP adresser og porter som brukes av noder inn i ipnports.txt filen.

2. Start serveren og oppgi port på serveren:
```
java OnionServer.java -p <port>
```

3. Sørg for å ha riktig IP og port til server i din klient. Angi hvor mange noder som du vil koble opp mot:
```
java OnionClient.java -p <port til server> -ip <ip til server> -n <antall noder> 
```

Kjør klient og vent til klienten setter opp tilkoblingen. Når klienten forteller deg at "setup is complete"
kan du begynne å sende og motta meldinger.

### Dokumentasjon
[Link til GitHub Pages](https://bragem.github.io/nettverk_prosjekt/)

### Eksterne kilder
En haug med stack-overflow linker og søkerlogg er tilgjengelige ved forespørsel.


Link til docs: https://bragem.github.io/nettverk_prosjekt/
For å generere ny javadoc kjør mvn javadoc:javdoc
