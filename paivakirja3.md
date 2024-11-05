# Oppimispäiväkirja: Git projektissa

__Mitä hyötyä voisi olla versionhallinnasta, jos kehität projektia yksin?__

Versionhallinnasta sekä hosting palveluista on ehdottomasti suuri hyöty, vaikka projektia tekisi yksin. Se mahdollistaa committien tarkastelemisen ja esimerkiksi täten voidaan helposti palata taaksepäin aiemmin toimivaan versioon. Versionhallinnan avulla voidaan myös palauttaa mieleen, mitä on viimeksi saanut tehtyä ja minkälaisia muutokset oikeasti olivat. Commit viestejä voidaankin käyttää myös ikään kuin kokoelmana siitä, mitä ollaan tehty. Commit viestit yksinkertaistavat rakennetta ja voivat auttaa myös debuggaamisessa. Tämän lisäksi myös jos työ vaatii sitä, että se toteutetaan eri haaroissa, on versionhallinnalla myös siihen mahdollisuus. Tämän lisäksi mergejen tapahtuessa versionhallinta myös auttaa siinä, että käyttäjälle ilmoitetaan konfliktit ja autetaan tätä ne ratkaisemaan.

Tämän lisäksi puskemalla tiedot esimerkiksi githubiin, saat myös mahdollisuuden työstää samaa projektia esimerkiksi eri laitteilla. Versionhallinta auttaa myös siis siinä suhteessa, että et kehittäjänä ole sidottuna tiettyyn aikaan, etkä paikkaan.

Tämän lisäksi hosting palvelut tarjoavat versionhallinnan tueksi myös monia hyötyjä. Yksi tällainen voisi olla esimerkiksi webhookit sovelluksen julkaisun jälkeen päivittämisen yhteydessä. Ne tarjoavat myös mahdollisuuden tehdä mergejä ja pieniä lisätoiminteita käyttöliittymän kautta.

__Mitä hyötyä voisi olla versionhallinnasta, jos projektissa on useita kehittäjiä?__

Hyödyt ovat tiimissä myös osittain samanlaiset, mutta erityisen hyödyllisenä kuitenkin voidaan pitää sitä faktaa, että moni kehittäjä voi työskennellä projektissa, jopa samassa tiedostossa samaan aikaan. Tämä on todella yleinen toimintatapa, sekä se toimii versionhallinnan avulla varsin kivuttomasti. Jokainen kehittäjä saa muiden tekemät muutokset näkyviin myös itsellään hakemalla one etärepositoriosta esimerkiksi fetchillä tai pullilla (joka yhdistää fetchin ja mergen). Sopimalla yhteisistä toimintatavoista, sekä varmistamalla, että jokainen tiimin kehittäjä osaa käyttää versionhallintaa hyödykseen voidaan luoda siis projektiin alusta, jossa jokainen voi edistää projektia

Versionhallinta myös mahdollistaa sen, että muutokset haetaan helposti. Sen avulla esimerkiksi jokaista muutettua tiedostoa ei tarvitse erikseen lähteä lähettämään jollain kanavalla tiimiläisille, vaan puskemalla muutokset varmistetaan, että en ovat yhden komennon päässä. Tämä mahdollistaa myös sen, että jokaisella kehittäjä on samankaltainen kehitysympäristö, eivätkä niiden sisällöt eroa merkittävästi toisistaan.

Tiimeille vielä erikseen on hyödyllistä käyttää myös pull requesteja, joiden avulla voidaan viestittää, että jokin muutos olisi tulossa. Siihen voidaan asettaa esimerkiksi reviewereitä, jotka tarkastettuaan muutoksen, voivat hyväksyä sen. Toisin sanoen, versionhallinta lisää tiimin sisäistä ymmärrystä sekä toiminnasta tulee läpinäkyvämpää (mikäli versionhallinta on toteutettu oikein)

Versionhallinta yksinkertaistaa ja nopeuttaa tiimissä työskentelyä. Aiemmin mainitsemani lisäksi tiimeille on myös käytössä kaikki samat ominaisuudet, mitä ensimmäiseen kohtaan luettelin (nähdään helposti kuka, mitä ja million, voidaan liikkua helposti eri versioiden välillä sekä käyttää hostingpalveluiden webkehittämistä helpottavia palveluita, kuten erilaiset automatisoinnit)

__Miten järjestäisit projektitiimin versionhallinnan 3-4 hengen ohjelmistoprojektikurssilla? Laadi tiimiläisille lyhyt ohje, miten projektissa toimitaan.__

Projektissa tulisi olla kolmen tyylisiä haaroja. Main haara, joka on ikään kuin julkaisuhaara. Sinne liitetään ainoastaan jo testatut tiedot, jotka ovat valmiita julkaistavaksi. Toinen haara on develop, johon muutokset yhdistetään. Tämä on ikään kuin testaamishaara, jossa toiminnallisuus varmistetaan ja tiimin kehittäjien muutokset kootaan tänne, jotta ne ovat yhteensopivia. Viimeinen haaratyyppi ovat feature haarat. Näitä luodaan monia, kun uusia featureita kehitetään (1/haara). Näin voidaan keskittää kehittäminen helposti oikeisiin paikkoihin, mistä muut tiimiläiset ne löytävät. 

Feature haarasta kehittäjät saisivat itsenäisesti yhdistää develop haaraan, jotta toiminnallisuudet voidaan testata siellä. Feature haaroja voi jokainen kehittäjä myös luoda, jos vaikuttaa siltä, että kehitettävälle ominaisuudelle ei ole järkevää kohdetta. Jokainen keskisuuri - suuri muutos tehdään oman featuren kautta. Ne nimetään periaateella feature/ominaisuuden_nimi. Pieniä muutoksia voidaan laittaa suoraan develop haaraan. Develop haaran yhdistäminen mainiin sovitaan tiimin kanssa aina erikseen. Jos sille on tarvetta kehittäjät viestivät siitä toisilleen ja luodaan pull/merge request johon projektin johtaja tai muut kehittäjät asetataan reviweriksi. Hyväksynnän jälkeen haara voidaan yhdistää requestin kautta.

Feature haarat voidaan myös yhdistämisen jälkeen poistaa, mikäli muutosta tehtyyn asiaan ei enää tarvita. Repo tulisi pitää mahdollisimman siistinä.

Commit viestit tulisivat olla mielestäni myös tarkkoja. Riippuen tiimin kokoonpanosta, kieli tulee olla jokaiselle ymmärrettävä. Commit viestit olisi hyvä pitää max 2 virkkeen mittaisina. Mieluiten yhdessä virkkeessä. Yksi commit / yksi asia. Commit viestit pitää olla tarpeeksi kuvaavia, siten, että niissä kerrotaan mitä commitissa tehtiin. Mieluiten commit viestit eivät sisällä skandeja, sekä ovat käskymuodossa, jotta kommunikaatio on jokaisen jäsenen kohdalla samanlaista.

Jos tiimiläisille sattuu konflikteja, ne tulisi ratkaista mieluiten niiden toimijoiden välillä, jotka ovat ne tehneet. Täten tiimiläiset saavat yhteisymmärryksen, mitä ollaan tekemässä, kumpi ratkaisu sopii tilanteeseen ja tavoitteeseen sekä miten tullaan toimimaan.

__Kommenttini opintojaksosta, esim. sisällöstä, materiaalista, työmäärästä, hyödyllisyydestä, työmäärästä. Mitä toivoisit olevan enemmän, mitä vähemmän?__

Omasta mielestäni opintojakso on hyödyllinen varsinkin sellaiselle henkilölle, joka ei paljoa gitin kanssa ole toiminut. Itselleni tämä oli hyvää kertausta ja monia uusiakin asioita löytyi. Sisältö oli pääsääntöisesti selkeää, mutta muutamassa kohdassa itse ainakin jäin miettimään, miten täytyy toimia. Olisi ehkä järkevää ilmoittaa heti alussa vaikka siitä, että kloonattuihin repoihin ei voi puskea mitään ja, ettei se ole vielä olennaista. Materiaalia oli mielestäni tarpeeksi ja ne olivat selkeitä. Välillä jäin miettimään, miten hello projektin tehtävistä tulisi vastata; tällaisia olivat eritysesti avoimet kysymykset, joihin päädyin itse tekemään oman markdown tiedoston ja vastaamaan niihin siellä. Työmäärän puolesta kurssi oli tarpeeksi laaja, eikä mielestäni päästä tekijää liian helpolla (jos tehtävien tekemiseen oikeasti keskittyy). Itse erityisesti pidin viimeisestä harjoituksesta, jossa repoon puskettiin botin avulla lisää tavaraa. Tämä simuloi oikeaa tilannetta useamman kehittäjän läsnäollessa hyvin (peilaten kurssin toteutustapaan). Jos jotain kehitettävää tai lisättävää laittaisin, niin itse tykkään oppia videoiden perusteella. Jos vaikka 1 video / aihe olisi mahdollista, voisin kuvitella, että henkilötkin, jotka eivät aiemmin gitiä olleet käyttäneet, ymmärtävät varmasti, mitä haetaan takaa.