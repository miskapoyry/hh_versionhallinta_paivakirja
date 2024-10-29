# Oppimispäiväkirja: Paikallinen git

__Mikä osion tehtävissä oli vaikeaa ja mikä helppoa? Mikä auttoi minua oppimaan? Miten selvitin esteet?__

Mielestäni osio oli itsessään helppo ja jouduin sen tekemään toista kertaa. Olin aiemman tiedoston saanut jotenkin hävitettyä, joten tein tämän osan ajatuksen kanssa uudellen. Mielestäni tässä osassa ei ollut vaikeaa ymmärrettävää, sillä käytän itse aktiivisesti gitiä (gitlab) työni kautta sekä githubia koulun ja omien projektien vuoksi. Minua auttoi oppimaan erityisesti se, että pääsee itse kokeilemaan ja ongelman sattuessa pystyy netistä usein löytämään ratkaisun.

Itselläni ei suurempia esteitä ollut. Kuitenkin sain yhden konfliktin aikaiseksi haarojen kanssa. Tämä selvitettiin merge editorissa valitsemalla incoming change. Jos muita ongelmia gitin kanssa olisi tullut, olisin varmaankin googlettanut ongelman, josta suurella todennäköisyydellä löytyy ratkaisu siihen.

## Osiossa käyttämäni Git-komennot

| Komento | Kuvaus |
| --------| ------ |
| git clone | Kloonaa repon hakemistoon jossa olet |
| git init | Initialisoi repon uutta git projektia tehdessä, jotta git toiminnot saadaan käyttöön |
| git add | Lisää tekemäsi muutokset välitilaan |
| git commit -m | Tallentaa muutokset antamallasi viestillä |
| git log | Näet tekemäsi tallennukset ja tietoja niistä (tekijä, aika, commit hash) |
| git reset | Poistaa addatut muutokset valitsemastasi tiedostosta tai tiedostoista |
| git restore | Muuttaa valitun esim tiedosto, tiedostot tai koko repon edellisen commitin määrittämään tilaan |
| git branch | Näyttää haarat tai lisäämällä nimi perään luo uuden haaran |
| git checkout tai git switch | Vaihtaa haarojen välillä |
| git merge | yhdistää kahden (nykyisen) ja loppuun määritellyn haaran koodin toisiinsa |
| git rm | Poistaa määritellyn tiedoston |
| git clean | Poistaa untracked filet (-f forcettaa toiminnon) |
| git status | Näet statuksen siitä, mitä on repossasi muuttunut |