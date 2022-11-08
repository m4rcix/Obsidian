# Készülés AD CTF-re

Sok helyen tudnánk javítani a szervezettségünkön, hogy eredményesebbek legyünk AD CTF-eken.
Ezeket a dolgokat szedtük két listába, az egyik a CTF előtti feladatokat foglalja össze, a másik a CTF alattiakat.
Mindkét esetben a listában korábban szereplő elemek fontosabbak.

## CTF előtt

1. Arborétum tesztelés
  - **Ok**: Arborétum nehezen kezelhető volt, több esetben nem működött.
  - **Döntés**: Arborétumot intenzíven teszteljük a verseny előtt. Ehhez Pepe vállalta, hogy összerak egy banálisan egyszerű sérülékeny szolgáltatás és FLAG botot.
    Az egyik core alkalmon mindenki felhúzza magánál az Arborétumot és ütjük a tesztrendszert.
2. Infra checklist
  - **Ok**: A verseny alatt sok támadást el tudtunk volna hárítani, ha szisztematikusan végigmegyünk egy listán és hardeneljük az infránk (pl. nc, curl, wget törlése).
  - **Döntés**: Geri és Balázs csinálnak csatornát Discordon, amibe mindenki bedobálja az ötleteit, hogy mit lehetnek hasonló egyszerűséggel hardenelni az infrán.
    Ez után az ötletekből csinálnak egy prioritásos listát, amin a verseny kezdetén az infra csapat végigmegy.
3. Előre készülni a versenyre :kekw:
  - **Ok**: A verseny alatt volt olyan probléma az infrával, amit előre készüléssel korábban orvosolni tudunk volna. Többen nem olvasták el a szabályzatot.
  - **Döntés**: Verseny előtt legalább egy héttel, vagy amint lehetőség van rá, összerakjuk az infrát. Kijelölünk egy embert a verseny előtt, aki fel van hatalmazva, hogy
    mindenkit piszkáljon, hogy olvassa el a szabályzatot, valamint piszkálja az infra csapatot, hogy legyen kész időben a rendszer.
    Az előre készülés része a backup exploit script készítése, amit az Arborétum kiesése esetén vetünk be, ezt Marcix vállalta.
4. Pcap gyűjtés feljesztése
  - **Ok**: Voltak hiányosságai a jelenlegi pcap gyűjtésnek (pl mi támadásaink is benne voltak)
  - **Döntés**: Geri és Pepe tovább finomítják a rendszert. Implementálják, hogy csak bejövő támadások látszódjanak, ha kell feloldják az SSL-t és utána capture-ölnek.
    Hozzáadnak json metaadatokat a pcap-hez, mint az adott tick flag_id-i, ellopott flagek száma stb.
5. Netfilter queue használata
  - **Ok**: Netfilter queue-val egy csomó támadást el tudnánk hárítani, ha rátanulunk a flag bot működésére és minden másra szabályokat írunk.
  - **Döntés**: Amennyiben lesz ideje, Pepe mesél majd kicsit a netfilter queue-król. Minden feladathoz lesz egy valaki, aki tudja kezelni a queue-kat
    és az adott feladatra be tudja állítani a szabályokat.

## CTF alatt

1. Feladatok felosztása csapatokra, személyekre a verseny előtt
  - **Ok**: Voltak feladatok, amikkel senki sem foglalkozott, pedig könnyen lehetett volna velük szemben védekezni. Infra kezelés nehézkes volt.
  - **Döntés**: A verseny előtt a résztetők számától függően alakítunk csapatokat minden feladatra, lesz ezen kívül infra és talán Arborétum csapat is.
    Minden csapatnak lesz egy tapasztaltabb felelőse. Ő lesz az, aki koordinálja a részfeladatokat. Egy chall-hoz tartozó csapat feladatai
    pl. patch-elni a feladatot, beérkező pcap-ek alapján támadni, netfilter queue szabályokat írni az adott feladathoz, életbentartani a service-t
    A verseny alatt időnként ez a néhány felelős ember összegyűlik és pár percben megdumálják az állapotot, amennyiben szükséges.
    Azt, hogy ki épp melyik csapatban van, Discord voice csatornán vagy google sheet-ben vezetjük, hogy látszon, hogy ki mit csinál, hova kell még ember.
2. Infra checklist végrehajtása:
  - **Ok**: Hogy ne csak a semmiért legyen a checklist :D
  - **Döntés**: Fontos, hogy az infra csapat, miután megismerte a service-eket, végrehajtsa a checklistet.
3. Patch deployment
  - **Ok**: Nem jó, ha az infra csapat feladata, hogy a patch-eket folyton deploy-olja.
  - **Döntés**: A patch-ek bevezetése az éles szolgáltatásban a feladattal foglalkozó emberek feladata.
    Minden csapatból valakinek van joga belépni a vulnboxba és ki tudja rakni a javított változatot.
4. Időnkénti info szinkronizálás
  - **Ok**: Hogy lássu, hol mennyi erőforrás van, hol van kevés ember, sok feladatra.
  - **Döntés**: 1-2 óránként minden csapatból egy ember találkozik a többi küldönccel és megdumálják, hogy mi az állapot. Újraszervezük az embereket, ha szükséges.
5. Körök végén a korábbi flag-ek törlése
  - **Ok**: Fölösleges, hogy olyan valid flag-ek is legyenek a szolgáltatásunkban, amit a bot már nem ellenőriz, de allopható és X körig még pontot ér a beadása.
  - **Döntés**: Minden feladattal foglalkozó csapat felelősége implementálni, hogy töröljék a korábbi, már nem használatos flag-eket a szolgáltatásból.
6. PCAP + service DoS
  - **Ok**: Másoknál nehét lesz keresni a pcap-ben, ha nagyon sok kapcsolatot/forgalmat generálunk feléjük.
  - **Döntés**: Minden csapat implementáljon egy dummy exploit-ot, amit az Arborétum tud futtatni támadásként, ezzel megnehezítjük, hogy a védők megtalálják
    a számukra hasznos információval szolgáló TCP stream-et, vagy csomagokat.