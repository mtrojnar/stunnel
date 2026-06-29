---
lang: pl-PL
---

# NAZWA

stunnel - uniwersalny tunel protokołu TLS

# SKŁADNIA

-   **Unix:** **stunnel** \[`PLIK`\] \| `-fd N` \| `-help` \| `-version` \| `-sockets` \| `-options`

-   **WIN32:** **stunnel** \[ \[ `-install` \| `-uninstall` \| `-start` \| `-stop` \| `-reload` \| `-reopen` \| `-exit` \] \[`-quiet`\] \[`PLIK`\] \] \| `-help` \| `-version` \| `-sockets` \| `-options`

# OPIS

Program **stunnel** został zaprojektowany do opakowywania w protokół *TLS* połączeń pomiędzy zdalnymi klientami a lokalnymi lub zdalnymi serwerami. Przez serwer lokalny rozumiana jest aplikacja przeznaczona do uruchamiania przy pomocy *inetd*. Stunnel pozwala na proste zestawienie komunikacji serwerów nie posiadających funkcjonalności *TLS* poprzez bezpieczne kanały *TLS*.

**stunnel** pozwala dodać funkcjonalność *TLS* do powszechnie stosowanych demonów *inetd*, np. *pop3* lub *imap*, do samodzielnych demonów, np. *nntp*, *smtp* lub *http*, a nawet tunelować ppp poprzez gniazda sieciowe bez zmian w kodzie źródłowym.

# OPCJE

-   **PLIK**

    użyj podanego pliku konfiguracyjnego

-   **-fd N** (tylko Unix)

    wczytaj konfigurację z podanego deskryptora pliku

-   **-help**

    drukuj listę wspieranych opcji

-   **-version**

    drukuj wersję programu i domyślne wartości parametrów

-   **-sockets**

    drukuj domyślne opcje gniazd

-   **-options**

    drukuj wspierane opcje TLS

-   **-install** (tylko Windows NT lub nowszy)

    instaluj serwis NT

-   **-uninstall** (tylko Windows NT lub nowszy)

    odinstaluj serwis NT

-   **-start** (tylko Windows NT lub nowszy)

    uruchom serwis NT

-   **-stop** (tylko Windows NT lub nowszy)

    zatrzymaj serwis NT

-   **-reload** (tylko Windows NT lub nowszy)

    przeładuj plik konfiguracyjny uruchomionego serwisu NT

-   **-reopen** (tylko Windows NT lub nowszy)

    otwórz ponownie log uruchomionego serwisu NT

-   **-exit** (tylko Win32)

    zatrzymaj uruchomiony program

-   **-quiet** (tylko Win32)

    nie wyświetlaj okienek z komunikatami

# PLIK KONFIGURACYJNY

Linia w pliku konfiguracyjnym może być:

-   pusta (ignorowana)

-   komentarzem rozpoczynającym się znakiem ';' (ignorowana)

-   parą 'nazwa_opcji = wartość_opcji'

-   tekstem '\[nazwa_usługi\]' wskazującym początek definicji usługi

Parametr adres może być:

-   numerem portu

-   oddzieloną średnikiem parą adresu (IPv4, IPv6, lub nazwą domenową) i numeru portu

-   ścieżką do gniazda Unix (tylko Unix)

## OPCJE GLOBALNE

-   **chroot** = KATALOG (tylko Unix)

    katalog roboczego korzenia systemu plików

    Opcja określa katalog, w którym uwięziony zostanie proces programu **stunnel** tuż po jego inicjalizacji, a przed rozpoczęciem odbierania połączeń. Ścieżki podane w opcjach *CApath*, *CRLpath*, *pid* oraz *exec* muszą być umieszczone wewnątrz katalogu podanego w opcji *chroot* i określone względem tego katalogu.

    Niektóre funkcje systemu operacyjnego mogą wymagać dodatkowych plików umieszczonych w katalogu podanego w parametrze chroot:

    -   opóźnione rozwinięcie adresów DNS typowo wymaga /etc/nsswitch.conf i /etc/resolv.conf

    -   lokalizacja strefy czasowej w logach wymaga pliku /etc/timezone

    -   niektóre inne pliki mogą potrzebować plików urządzeń, np. /dev/zero lub /dev/null

-   **compression** = deflate \| zlib \| zstd \| brotli

    wybór algorytmu kompresji przesyłanych danych

    domyślnie: bez kompresji

    Kompresja danych jest dostępna wyłącznie dla protokołu TLS 1.2 i starszych. Wymaga obniżenia **securityLevel** do 1 począwszy od **OpenSSL 1.1.0**.

    Algorytmy zlib, zstd i brotli są wyłączone w domyślnej konfiguracji OpenSSL.

    Algorytmy zstd i brotli zostały dodane w **OpenSSL 3.2**.

    Kompresja danych stanowi ryzyko w aplikacjach, które umożliwiają napastnikowi wstrzyknięcie wybranego tekstu jawnego.

    Algorytm deflate jest standardową metodą kompresji zgodnie z RFC 1951.

    **Uwaga**: Kompresja TLS może umożliwiać ataki prowadzące do odzyskania tekstu jawnego, takie jak CRIME, gdy dane kontrolowane przez atakującego są kompresowane razem danymi chronionymi.

-   **debug** = \[PODSYSTEM\].POZIOM

    szczegółowość logowania

    Poziom logowania można określić przy pomocy jednej z nazw lub liczb: emerg (0), alert (1), crit (2), err (3), warning (4), notice (5), info (6) lub debug (7). Zapisywane są komunikaty o poziomie niższym (numerycznie) lub równym podanemu. Domyślnym poziomem jest notice (5).

    Jakkolwiek użycie *debug = debug* lub *debug = 7* zapewnia najbardziej szczegółowe logi, ich zawartość jest użyteczna jedynie dla programistów zajmujących się stunnelem. Użyj tego poziomu logowania jedynie jeśli jesteś programistką/programistą stunnela, albo przygotowujesz szczegółowe informacje celem przesłania do wsparcia technicznego. W przeciwnym wypadku próba analizy zawartości logów **będzie** jedynie źródłem dodatkowego zamieszania.

    O ile nie wyspecyfikowano podsystemu użyty będzie domyślny: daemon. Podsystemy nie są wspierane przez platformę Win32.

    Wielkość liter jest ignorowana zarówno dla poziomu jak podsystemu.

-   **EGD** = ŚCIEŻKA_DO_EGD (tylko Unix)

    ścieżka do gniazda programu Entropy Gathering Daemon

    Opcja pozwala określić ścieżkę do gniazda programu Entropy Gathering Daemon używanego do zainicjalizowania generatora ciągów pseudolosowych biblioteki **OpenSSL**.

-   **engine** = auto \| IDENTYFIKATOR_URZĄDZENIA

    wybór silnika kryptograficznego

    domyślnie: bez wykorzystania silników kryptograficznych

    Sekcja PRZYKŁADY zawiera przykładowe konfiguracje wykorzystujące silniki kryptograficzne.

-   **engineCtrl** = KOMENDA\[:PARAMETR\]

    konfiguracja silnika kryptograficznego

-   **engineDefault** = LISTA_ZADAŃ

    lista zadań OpenSSL oddelegowanych do bieżącego silnika

    Parametrem jest lista oddzielonych przecinkami zadań OpenSSL, które mają zostać oddelegowane do bieżącego silnika kryptograficznego.

    W zależności od konkretnego silnika dostępne mogą być następujące zadania: ALL, RSA, DSA, ECDH, ECDSA, DH, RAND, CIPHERS, DIGESTS, PKEY, PKEY_CRYPTO, PKEY_ASN1.

-   **fips** = yes \| no

    tryb FIPS 140-2

    Opcja pozwala wyłączyć wejście w tryb FIPS, jeśli **stunnel** został skompilowany ze wsparciem dla FIPS 140-2.

    domyślnie: no (od wersji 5.00)

-   **foreground** = yes \| quiet \| no (tylko Unix)

    tryb pierwszoplanowy

    Użycie tej opcji powoduje, że **stunnel** nie przechodzi w tło.

    Parametr *yes* powoduje dodatkowo, że komunikaty diagnostyczne logowane są na standardowy strumień błędów (stderr) oprócz wyjść zdefiniowanych przy pomocy opcji *syslog* i *output*.

-   **iconActive** = PLIK_Z_IKONKĄ (tylko GUI)

    ikonka wyświetlana przy obecności aktywnych połączeń do usługi

    W systemie Windows ikonka to plik .ico zawierający obrazek 16x16 pikseli.

-   **iconError** = PLIK_Z_IKONKĄ (tylko GUI)

    ikonka wyświetlana, jeżeli nie został załadowany poprawny plik konfiguracyjny

    W systemie Windows ikonka to plik .ico zawierający obrazek 16x16 pikseli.

-   **iconIdle** = PLIK_Z_IKONKĄ (tylko GUI)

    ikonka wyświetlana przy braku aktywnych połączeń do usługi

    W systemie Windows ikonka to plik .ico zawierający obrazek 16x16 pikseli.

-   **log** = append \| overwrite

    obsługa logów

    Ta opcja pozwala określić, czy nowe logi w pliku (określonym w opcji *output*) będą dodawane czy nadpisywane.

    domyślnie: append

-   **output** = PLIK

    plik, do którego dopisane zostaną logi

    Użycie tej opcji powoduje dopisanie logów do podanego pliku.

    Do kierowania komunikatów na standardowe wyjście (na przykład po to, żeby zalogować je programem splogger z pakietu daemontools) można podać jako parametr urządzenie /dev/stdout.

-   **pid** = PLIK (tylko Unix)

    położenie pliku z numerem procesu

    Jeżeli argument jest pusty, plik nie zostanie stworzony.

    Jeżeli zdefiniowano katalog *chroot*, to ścieżka do *pid* jest określona względem tego katalogu.

-   **provider** = PROVIDER_ID

    Określa identyfikator dostawcy (provider), który ma być używany. PROVIDER_ID to unikalny identyfikator wskazujący na konkretnego dostawcę usług kryptograficznych.

    Opcja ta wymaga biblioteki OpenSSL w wersji 3.0 lub nowszej.

-   **providerParameter** = PROVIDER_ID:PARAMETER=VALUE

    Ustawia określony parametr dla wskazanego dostawcy. PROVIDER_ID identyfikuje dostawcę, PARAMETER to nazwa parametru, a VALUE to jego wartość. Ta opcja pozwala na dostosowanie konfiguracji wybranego dostawcy usług kryptograficznych.

    Opcja ta wymaga biblioteki OpenSSL w wersji 3.5 lub nowszej.

-   **RNDbytes** = LICZBA_BAJTÓW

    liczba bajtów do zainicjowania generatora pseudolosowego

-   **RNDfile** = PLIK

    ścieżka do pliku zawierającego losowe dane

    Biblioteka **OpenSSL** użyje danych z tego pliku do zainicjowania generatora pseudolosowego.

-   **RNDoverwrite** = yes \| no

    nadpisz plik nowymi wartościami pseudolosowymi

    domyślnie: yes (nadpisz)

-   **service** = SERWIS (tylko Unix)

    nazwa usługi

    Podana nazwa usługi będzie używana jako nazwa usługi dla inicjalizacji sysloga, oraz dla biblioteki TCP Wrapper w trybie *inetd*. Chociaż technicznie można użyć tej opcji w trybie w sekcji usług, to jest ona użyteczna jedynie w opcjach globalnych.

    domyślnie: stunnel

-   **setEnv** = VAR_NAME=VALUE

    Zmienia lub dodaje zmienną środowiskową dla procesów potomnych. Jeśli VAR_NAME już istnieje, jej wartość zostanie zaktualizowana; w przeciwnym razie zostanie utworzona nowa zmienna. Modyfikacja dotyczy tylko uruchamianych procesów potomnych i nie wpływa na bieżące środowisko.

-   **syslog** = yes \| no (tylko Unix)

    włącz logowanie poprzez mechanizm syslog

    domyślnie: yes (włącz)

-   **taskbar** = yes \| no (tylko WIN32)

    włącz ikonkę w prawym dolnym rogu ekranu

    domyślnie: yes (włącz)

## OPCJE USŁUG

Każda sekcja konfiguracji usługi zaczyna się jej nazwą ujętą w nawias kwadratowy. Nazwa usługi używana jest do kontroli dostępu przez bibliotekę libwrap (TCP wrappers) oraz pozwala rozróżnić poszczególne usługi w logach.

Jeżeli **stunnel** ma zostać użyty w trybie *inetd*, gdzie za odebranie połączenia odpowiada osobny program (zwykle *inetd*, *xinetd* lub *tcpserver*), należy przeczytać sekcję *TRYB INETD* poniżej.

-   **accept** = \[HOST:\]PORT

    nasłuchuje na połączenia na podanym adresie i porcie

    Jeżeli nie został podany adres, **stunnel** domyślnie nasłuchuje na wszystkich adresach IPv4 lokalnych interfejsów.

    Aby nasłuchiwać na wszystkich adresach IPv6 należy użyć:

        accept = :::port

-   **CAengine** = IDENTYFIKATOR_CA_W_ENGINE

    ładuje zaufane certyfikaty Centrum certyfikacji z silnika

    Opcja pozwala określić położenie pliku zawierającego certyfikaty używane przez opcję *verifyChain* lub *verifyPeer*.

    Opcja może być użyta wielokrotnie w pojedynczej sekcji.

    Aktualnie wspierane silniki: pkcs11, cng.

-   **CApath** = KATALOG_CA

    ładuje zaufane certyfikaty Centrum certyfikacji z katalogu

    Opcja określa katalog, w którym **stunnel** będzie szukał certyfikatów, jeżeli użyta została opcja *verifyChain* lub *verifyPeer*. Pliki z certyfikatami muszą posiadać specjalne nazwy XXXXXXXX.0, gdzie XXXXXXXX jest skrótem kryptograficznym reprezentacji DER nazwy podmiotu certyfikatu.

    Ta opcja może być również użyta do dostarczenia certyfikatu root CA, który jest niezbędny do prawidłowej weryfikacji OCSP stapling w trybie serwera.

    Funkcja skrótu została zmieniona w **OpenSSL 1.0.0**. Należy wykonać c_rehash przy zmianie **OpenSSL 0.x.x** na **1.x.x**.

    Jeżeli zdefiniowano katalog *chroot*, to ścieżka do *CApath* jest określona względem tego katalogu.

-   **CAfile** = PLIK_CA

    ładuje zaufane certyfikaty Centrum certyfikacji z pliku

    Opcja pozwala określić położenie pliku zawierającego certyfikaty używane przez opcję *verifyChain* lub *verifyPeer*.

    Ta opcja może być również użyta do dostarczenia certyfikatu root CA, który jest niezbędny do prawidłowej weryfikacji OCSP stapling w trybie serwera.

-   **CAstore** = URI_CA

    ładuje zaufane certyfikaty Centrum certyfikacji z zasobu wskazanego przez URI

    Opcja umożliwia załadowanie certyfikatów CA z zewnętrznego magazynu obsługiwanego przez mechanizm *OSSL_STORE*, takiego jak moduł PKCS#11 (np. token sprzętowy), systemowy magazyn certyfikatów lub zasób sieciowy.

    Opcja może być stosowana niezależnie od *CAfile* i *CAdir*, analogicznie służy do walidacji łańcucha certyfikatów przy użyciu opcji *verifyChain* lub *verifyPeer*, a także do weryfikacji OCSP stapling po stronie serwera.

    Opcja ta wymaga biblioteki OpenSSL w wersji 3.0 lub nowszej.

-   **cert** = PLIK_CERT \| URI

    plik z łańcuchem certyfikatów

    Opcja określa położenie pliku zawierającego certyfikaty używane przez program **stunnel** do uwierzytelnienia się przed drugą stroną połączenia. Plik powinien zawierać kompletny łańcuch certyfikatów począwszy od certyfikatu klienta/serwera, a skończywszy na samopodpisanym certyfikacie głównego CA. Obsługiwane są pliki w formacie PEM lub P12.

    Certyfikat jest konieczny, aby używać programu w trybie serwera. W trybie klienta certyfikat jest opcjonalny.

    Opcja **cert** może być podana wielokrotnie. Pierwszy napotkany certyfikat zostanie użyty jako certyfikat serwera lub klienta, natomiast kolejne będą traktowane jako elementy pośrednie łańcucha. Ta funkcjonalność wymaga biblioteki OpenSSL w wersji 1.0.2 lub nowszej.

    Jeżeli używany jest silnik kryptograficzny lub provider, to opcja **cert** pozwala wybrać identyfikator (PKCS#11 URI) używanego certyfikatu.

    Uwaga: provider wymaga OpenSSL 3.0 lub nowszego

-   **checkEmail** = EMAIL

    adres email podmiotu przedstawionego certyfikatu

    Pojedyncza sekcja może zawierać wiele wystąpień opcji **checkEmail**. Certyfikaty są akceptowane, jeżeli sekcja nie weryfikuje podmiotu certyfikatu, albo adres email przedstawionego certyfikatu pasuje do jednego z adresów email określonych przy pomocy **checkEmail**.

    Opcja ta wymaga biblioteki OpenSSL w wersji 1.0.2 lub nowszej.

-   **checkHost** = NAZWA_SERWERA

    nazwa serwera podmiotu przedstawionego certyfikatu

    Pojedyncza sekcja może zawierać wiele wystąpień opcji **checkHost**. Certyfikaty są akceptowane, jeżeli sekcja nie weryfikuje podmiotu certyfikatu, albo nazwa serwera przedstawionego certyfikatu pasuje do jednego nazw określonych przy pomocy **checkHost**.

    Opcja ta wymaga biblioteki OpenSSL w wersji 1.0.2 lub nowszej.

-   **checkIP** = IP

    adres IP podmiotu przedstawionego certyfikatu

    Pojedyncza sekcja może zawierać wiele wystąpień opcji **checkIP**. Certyfikaty są akceptowane, jeżeli sekcja nie weryfikuje podmiotu certyfikatu, albo adres IP przedstawionego certyfikatu pasuje do jednego z adresów IP określonych przy pomocy **checkIP**.

    Opcja ta wymaga biblioteki OpenSSL w wersji 1.0.2 lub nowszej.

-   **ciphers** = LISTA_SZYFRÓW

    lista dozwolonych szyfrów dla protokołów SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2

    Ta opcja nie wpływa na listę parametrów kryptograficznych dla protokołu TLSv1.3

    Parametrem tej opcji jest lista szyfrów, które będą użyte przy otwieraniu nowych połączeń TLS, np.: DES-CBC3-SHA:IDEA-CBC-MD5

-   **ciphersuites** = LISTA_PARAMETRÓW_KRYPTOGRAFICZNYCH

    lista dozwolonych parametrów kryptograficznych dla protokołu TLSv1.3

    Parametrem tej opcji są listy parametrów kryptograficznych w kolejności ich preferowania.

    Począwszy od **OpenSSL 3.0** opcja *ciphersuites* ignoruje nieznane szyfry.

    Opcja *ciphersuites* jest dostępna począwszy od **OpenSSL 1.1.1**.

    domyślnie: TLS_CHACHA20_POLY1305_SHA256: TLS_AES_256_GCM_SHA384: TLS_AES_128_GCM_SHA256

-   **client** = yes \| no

    tryb kliencki (zdalna usługa używa TLS)

    domyślnie: no (tryb serwerowy)

-   **config** = KOMENDA\[:PARAMETR\]

    komenda konfiguracyjna **OpenSSL**

    Komenda konfiguracyjna **OpenSSL** zostaje wykonana z podanym parametrem. Pozwala to na wydawanie komend konfiguracyjnych **OpenSSL** z pliku konfiguracyjnego stunnela. Dostępne komendy opisane są w podręczniku *SSL_CONF_cmd(3ssl)*.

    Możliwe jest wyspecyfikowanie wielu opcji **OpenSSL** przez wielokrotne użycie komendy **config**.

    Zamiast wyłączać *config = Curves:list_curves* użyj opcji *curves* w celu ustawienia krzywych eliptycznych.

    Opcja ta wymaga biblioteki OpenSSL w wersji 1.0.2 lub nowszej.

-   **connect** = \[HOST:\]PORT

    połącz się ze zdalnym serwerem na podany port

    Jeżeli nie został podany adres, **stunnel** domyślnie łączy się z lokalnym serwerem.

    Komenda może być użyta wielokrotnie w pojedynczej sekcji celem zapewnienia wysokiej niezawodności lub rozłożenia ruchu pomiędzy wiele serwerów.

-   **CRLpath** = KATALOG_CRL

    katalog List Odwołanych Certyfikatów (CRL)

    Opcja określa katalog, w którym **stunnel** będzie szukał list CRL używanych przez opcje *verifyChain* i *verifyPeer*. Pliki z listami CRL muszą posiadać specjalne nazwy XXXXXXXX.r0, gdzie XXXXXXXX jest skrótem listy CRL.

    Funkcja skrótu została zmieniona **OpenSSL 1.0.0**. Należy wykonać c_rehash przy zmianie **OpenSSL 0.x.x** na **1.x.x**.

    Jeżeli zdefiniowano katalog *chroot*, to ścieżka do *CRLpath* jest określona względem tego katalogu.

-   **CRLfile** = PLIK_CRL

    plik List Odwołanych Certyfikatów (CRL)

    Opcja pozwala określić położenie pliku zawierającego listy CRL używane przez opcje *verifyChain* i *verifyPeer*.

-   **curves** = lista

    krzywe ECDH odddzielone ':'

    Uwaga: ta opcja wpływa tylko na gniazda w trybie serwera.

    Wersje OpenSSL starsze niż 1.1.1 pozwalają na użycie tylko jednej krzywej.

    Listę dostępnych krzywych można uzyskać poleceniem:

        openssl ecparam -list_curves

    domyślnie:

        X25519:P-256:X448:P-521:P-384 (począwszy od OpenSSL 1.1.1)

        prime256v1 (OpenSSL starszy niż 1.1.1)

-   **logId** = TYP

    typ identyfikatora połączenia klienta

    Identyfikator ten pozwala rozróżnić wpisy w logu wygenerowane dla poszczególnych połączeń.

    Aktualnie wspierane typy:

    -   *sequential*

        Kolejny numer połączenia jest unikalny jedynie w obrębie pojedynczej instancji programu **stunnel**, ale bardzo krótki. Jest on szczególnie użyteczny przy ręcznej analizie logów.

    -   *unique*

        Ten rodzaj identyfikatora jest globalnie unikalny, ale znacznie dłuższy, niż kolejny numer połączenia. Jest on szczególnie użyteczny przy zautomatyzowanej analizie logów.

    -   *thread*

        Identyfikator wątku systemu operacyjnego nie jest ani unikalny (nawet w obrębie pojedynczej instancji programu **stunnel**), ani krótki. Jest on szczególnie użyteczny przy diagnozowaniu problemów z oprogramowaniem lub konfiguracją.

    -   *process*

        Identyfikator procesu (PID) może być użyteczny w trybie inetd.

    domyślnie: sequential

-   **debug** = POZIOM

    szczegółowość logowania

    Poziom logowania można określić przy pomocy jednej z nazw lub liczb: emerg (0), alert (1), crit (2), err (3), warning (4), notice (5), info (6) lub debug (7). Zapisywane są komunikaty o poziomie niższym (numerycznie) lub równym podanemu. Do uzyskania najwyższego poziomu szczegółowości można użyć opcji *debug = debug* lub *debug = 7*. Domyślnym poziomem jest notice (5).

-   **delay** = yes \| no

    opóźnij rozwinięcie adresu DNS podanego w opcji *connect*

    Opcja jest przydatna przy dynamicznym DNS, albo gdy usługa DNS nie jest dostępna przy starcie programu **stunnel** (klient VPN, połączenie wdzwaniane).

    Opóźnione rozwijanie adresu DNS jest włączane automatycznie, jeżeli nie powiedzie się rozwinięcie któregokolwiek z adresów *connect* dla danej usługi.

    Opóźnione rozwijanie adresu automatycznie aktywuje *failover = prio*.

    domyślnie: no

-   **engineId** = NUMER_URZĄDZENIA

    wybierz silnik kryptograficzny dla usługi

-   **engineNum** = NUMER_URZĄDZENIA

    wybierz silnik kryptograficzny dla usługi

    Urządzenia są numerowane od 1 w górę.

-   **exec** = ŚCIEŻKA_DO_PROGRAMU

    wykonaj lokalny program przystosowany do pracy z superdemonem inetd

    Jeżeli zdefiniowano katalog *chroot*, to ścieżka do *exec* jest określona względem tego katalogu.

    Na platformach Unix ustawiane są następujące zmienne środowiskowe: REMOTE_HOST, REMOTE_PORT, SSL_CLIENT_DN, SSL_CLIENT_I_DN.

-   **execArgs** = \$0 \$1 \$2 \...

    argumenty do opcji *exec* włącznie z nazwą programu (\$0)

    Cytowanie nie jest wspierane w obecnej wersji programu. Argumenty są rozdzielone dowolną liczbą białych znaków.

-   **failover** = rr \| prio

    Strategia wybierania serwerów wyspecyfikowanych parametrami \"connect\".

    -   *rr*

        round robin - sprawiedliwe rozłożenie obciążenia

    -   *prio*

        priority - użyj kolejności opcji w pliku konfiguracyjnym

    domyślnie: prio

-   **ident** = NAZWA_UŻYTKOWNIKA

    weryfikuj nazwę zdalnego użytkownika korzystając z protokołu IDENT (RFC 1413)

-   **include** = KATALOG

    wczytaj fragmenty plików konfiguracyjnych z podanego katalogu

    Pliki są wczytywane w rosnącej kolejności alfabetycznej ich nazw. Rekomendowana konwencja nazewnictwa plików

    dla opcji globalnych:

        00-global.conf

    dla lokalnych opcji usług:

        01-service.conf

        02-service.conf

-   **key** = PLIK_KLUCZA \| URI

    klucz prywatny do certyfikatu podanego w opcji *cert*

    Klucz prywatny jest potrzebny do uwierzytelnienia właściciela certyfikatu. Ponieważ powinien on być zachowany w tajemnicy, prawa do jego odczytu powinien mieć wyłącznie właściciel pliku. W systemie Unix można to osiągnąć komendą:

        chmod 600 keyfile

    Jeżeli używany jest silnik kryptograficzny lub provider, to opcja **key** pozwala wybrać identyfikator (PKCS#11 URI) używanego klucza prywatnego.

    Uwaga: provider wymaga OpenSSL 3.0 lub nowszego

    domyślnie: wartość opcji *cert*

-   **libwrap** = yes \| no

    włącz lub wyłącz korzystanie z /etc/hosts.allow i /etc/hosts.deny.

    domyślnie: no (od wersji 5.00)

-   **local** = HOST

    IP źródła do nawiązywania zdalnych połączeń

    Domyślnie używane jest IP najbardziej zewnętrznego interfejsu w stronę serwera, do którego nawiązywane jest połączenie.

-   **OCSP** = URL

    responder OCSP do weryfikacji certyfikatu drugiej strony połączenia

-   **OCSPaia** = yes \| no

    weryfikuj certyfikaty przy użyciu respondertów AIA

    Opcja *OCSPaia* pozwala na weryfikowanie certyfikatów przy pomocy listy URLi responderów OCSP przesłanych w rozszerzeniach AIA (Authority Information Access).

-   **OCSPflag** = FLAGA_OCSP

    flaga respondera OCSP

    Aktualnie wspierane flagi: NOCERTS, NOINTERN, NOSIGS, NOCHAIN, NOVERIFY, NOEXPLICIT, NOCASIGN, NODELEGATED, NOCHECKS, TRUSTOTHER, RESPID_KEY, NOTIME

    Aby wyspecyfikować kilka flag należy użyć *OCSPflag* wielokrotnie.

-   **OCSPnonce** = yes \| no

    wysyłaj i weryfikuj OCSP nonce

    Opcja **OCSPnonce** zabezpiecza protokół OCSP przed atakami powtórzeniowymi. Ze względu na złożoność obliczeniową rozszerzenie nonce jest zwykle wspierane jedynie przez wewnętrzne (np. korporacyjne), a nie przez publiczne respondery OCSP.

-   **OCSPrequire** = yes \| no

    wymagaj rozstrzygającej odpowiedzi respondera OCSP

    Wyłączenie tej opcji pozwala na zaakceptowanie połączenia pomimo braku otrzymania rozstrzygającej odpowiedzi OCSP ze staplingu i bezpośredniego żądania wysłanego do respondera.

    domyślnie: yes

-   **options** = OPCJE_SSL

    opcje biblioteki **OpenSSL**

    Parametrem jest nazwa opcji zgodnie z opisem w *SSL_CTX_set_options(3ssl)*, ale bez przedrostka *SSL_OP\_*. *stunnel -options* wyświetla opcje dozwolone w aktualnej kombinacji programu *stunnel* i biblioteki *OpenSSL*.

    Aby wyspecyfikować kilka opcji należy użyć *options* wielokrotnie. Nazwa opcji może być poprzedzona myślnikiem (\"-\") celem wyłączenia opcji.

    Na przykład, dla zachowania kompatybilności z błędami implementacji TLS w programie Eudora, można użyć opcji:

        options = DONT_INSERT_EMPTY_FRAGMENTS

    domyślnie:

        options = NO_SSLv2
        options = NO_SSLv3

    Począwszy od **OpenSSL 1.1.0**, zamiast wyłączać określone wersje protokołów TLS użyj opcji *sslVersionMax* lub *sslVersionMin*.

-   **protocol** = PROTOKÓŁ

    negocjuj TLS podanym protokołem aplikacyjnym

    Opcja ta włącza wstępną negocjację szyfrowania TLS dla wybranego protokołu aplikacyjnego. Opcji *protocol* nie należy używać z szyfrowaniem TLS na osobnym porcie.

    Aktualnie wspierane protokoły:

    -   *cifs*

        Nieudokumentowane rozszerzenie protokołu CIFS wspierane przez serwer Samba. Wsparcie dla tego rozszerzenia zostało zarzucone w wersji 3.0.0 serwera Samba.

    -   *capwin*

        Wsparcie dla aplikacji <https://www.capwin.org/>

    -   *capwinctrl*

        Wsparcie dla aplikacji <https://www.capwin.org/>

        Ten protokół jest wspierany wyłącznie w trybie klienckim.

    -   *connect*

        Negocjacja RFC 2817 - *Upgrading to TLS Within HTTP/1.1*, rozdział 5.2 - *Requesting a Tunnel with CONNECT*

        Ten protokół jest wspierany wyłącznie w trybie klienckim.

    -   *imap*

        Negocjacja RFC 2595 - *Using TLS with IMAP, POP3 and ACAP*

    -   *ldap*

        Negocjacja RFC 2830 - *Lightweight Directory Access Protocol (v3): Extension for Transport Layer Security*

    -   *nntp*

        Negocjacja RFC 4642 - *Using Transport Layer Security (TLS) with Network News Transfer Protocol (NNTP)*

        Ten protokół jest wspierany wyłącznie w trybie klienckim.

    -   *pgsql*

        Negocjacja <https://www.postgresql.org/docs/8.3/static/protocol-flow.html#AEN73982>

    -   *pop3*

        Negocjacja RFC 2449 - *POP3 Extension Mechanism*

    -   *proxy*

        Przekazywanie oryginalnego IP klienta przez protokół HAProxy PROXY w wersji 1 <https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt>

    -   *smtp*

        Negocjacja RFC 2487 - *SMTP Service Extension for Secure SMTP over TLS*

    -   *socks*

        Wspierany jest protokół SOCKS w wersjach 4, 4a i 5. Protokół SOCKS enkapsulowany jest w protokole TLS, więc adres serwera docelowego nie jest widoczny dla napastnika przechwytującego ruch sieciowy.

        <https://www.openssh.com/txt/socks4.protocol>

        <https://www.openssh.com/txt/socks4a.protocol>

        Nie jest wspierana komenda BIND protokołu SOCKS. Przesłana wartość parametru USERID jest ignorowana.

        Sekcja PRZYKŁADY zawiera przykładowe pliki konfiguracyjne VPNa zbudowanego w oparciu o szyfrowany protokół SOCKS.

-   **protocolAuthentication** = UWIERZYTELNIENIE

    rodzaj uwierzytelnienia do negocjacji protokołu

    Opcja ta jest wpierana wyłącznie w klienckich protokołach 'connect' i 'smtp'.

    W protokole 'connect' wspierane jest uwierzytelnienie 'basic' oraz 'ntlm'. Domyślnym rodzajem uwierzytelnienia protokołu 'connect' jest 'basic'.

    W protokole 'smtp' wspierane jest uwierzytelnienie 'plain' oraz 'login'. Domyślnym rodzajem uwierzytelnienia protokołu 'smtp' jest 'plain'.

-   **protocolDomain** = DOMENA

    domena do negocjacji protokołu

    W obecnej wersji opcja ma zastosowanie wyłącznie w protokole 'connect'.

-   **protocolHeader** = NAGŁÓWEK

    nagłówek do negocjacji protokołu

    W obecnej wersji opcja ma zastosowanie wyłącznie w protokole 'connect'.

-   **protocolHost** = ADRES

    adres hosta do negocjacji protokołu

    Dla protokołu 'connect', *protocolHost* określa docelowy serwer TLS, do którego połączyć ma się proxy. Adres serwera proxy, do którego łączy się **stunnel**, musi być określony przy pomocy opcji *connect*.

    Dla protokołu 'smtp', *protocolHost* określa wartość HELO/EHLO wysyłanego przy negocjacji klienta.

-   **protocolPassword** = HASŁO

    hasło do negocjacji protokołu

    Opcja ta jest wspierana wyłącznie w klienckich protokołach 'connect' i 'smtp'.

-   **protocolUsername** = UŻYTKOWNIK

    nazwa użytkownika do negocjacji protokołu

    Opcja ta jest wspierana wyłącznie w klienckich protokołach 'connect' i 'smtp'.

-   **PSKidentity** = TOŻSAMOŚĆ

    tożsamość klienta PSK

    *PSKidentity* może zostać użyte w sekcjach klienckich do wybrania tożsamości użytej do uwierzytelnienia PSK. Opcja jest ignorowana w sekcjach serwerowych.

    domyślnie: pierwsza tożsamość zdefiniowana w pliku *PSKsecrets*

-   **PSKsecrets** = PLIK

    plik z tożsamościami i kluczami PSK

    Każda linia pliku jest w następującym formacie:

        TOŻSAMOŚĆ:KLUCZ

    Szesnastkowe klucze są automatycznie konwertowane do postaci binarnej. Klucz musi być mieć przynajmniej 16 bajtów, co w przypadku kluczy szesnastkowych przekłada się na przynajmniej 32 znaki. Należy ograniczyć dostęp do czytania lub pisania do tego pliku.

-   **pty** = yes \| no (tylko Unix)

    alokuj pseudo-terminal dla programu uruchamianego w opcji 'exec'

-   **redirect** = \[HOST:\]PORT

    przekieruj klienta, któremu nie udało się poprawnie uwierzytelnić przy pomocy certyfikatu

    Opcja działa wyłącznie w trybie serwera. Część negocjacji protokołów jest niekompatybilna z opcją *redirect*.

-   **renegotiation** = yes \| no

    pozwalaj na renegocjację TLS

    Zastosowania renegocjacji TLS zawierają niektóre scenariusze uwierzytelniania oraz renegocjację kluczy dla długotrwałych połączeń.

    Z drugiej strony własność na może ułatwić trywialny atak DoS poprzez wygenerowanie obciążenia procesora:

    <https://vincent.bernat.im/en/blog/2011-ssl-dos-mitigation.html>

    Warto zauważyć, że zablokowanie renegocjacji TLS nie zabezpiecza w pełni przed opisanym problemem.

    domyślnie: yes (o ile wspierane przez **OpenSSL**)

-   **reset** = yes \| no

    sygnalizuj wystąpienie błędu przy pomocy flagi TCP RST

    Opcja nie jest wspierana na niektórych platformach.

    domyślnie: yes

-   **retry** = yes \| no \| OPÓŹNIENIE

    połącz ponownie sekcję connect+exec po rozłączeniu

    Wartość parametru OPÓŹNIENIE określa liczbę milisekund oczekiwania przed wykonaniem ponownego połączenia. \"retry = yes\" jest synonimem dla \"retry = 1000\".

    domyślnie: no

-   **securityLevel** = POZIOM

    ustaw poziom bezpieczeństwa

    Znaczenie każdego poziomu opisano poniżej:

    -   poziom 0

        Wszystko jest dozwolone.

    -   poziom 1

        Poziom bezpieczeństwa zapewniający minimum 80 bitów bezpieczeństwa. Żadne parametry kryptograficzne oferujące poziom bezpieczeństwa poniżej 80 bitów nie mogą zostać użyte. W związku z tym RSA, DSA oraz klucze DH krótsze niż 1024 bity, a także klucze ECC krótsze niż 160 bitów i wszystkie eksportowe zestawy szyfrów są niedozwolone. Użycie SSLv2 jest zabronione. Wszelkie listy parametrów kryptograficznych używające MD5 do MAC są zabronione. Począwszy od OpenSSL 3.0 wersje TLS starsze niż 1.2 są wyłączone.

    -   poziom 2

        Poziom bezpieczeństwa zapewniający 112 bitów bezpieczeństwa. W związku z tym RSA, DSA oraz klucze DH krótsze niż 2048 bitów, a także klucze ECC krótsze niż 224 bity są niedozwolone. Oprócz wyłączeń z poziomu 1 zabronione jest także korzystanie z zestawów szyfrów używających RC4. Kompresja jest wyłączona. Użycie SSLv3 jest zabronione dla wersji OpenSSL starszych niż 3.0.

    -   poziom 3

        Poziom bezpieczeństwa zapewniający 128 bitów bezpieczeństwa. W związku z tym RSA, DSA oraz klucze DH krótsze niż 3072 bity, a także klucze ECC krótsze niż 256 bitów są niedozwolone. Oprócz wyłączeń z poziomu 2 zabronione jest także korzystanie z zestawów szyfrów nie zapewniających utajniania z wyprzedzeniem (forward secrecy). Bilety sesji są wyłączone. Wersje TLS starsze niż 1.1 są zabronione dla wersji OpenSSL starszych niż 3.0.

    -   poziom 4

        Poziom bezpieczeństwa zapewniający 192 bity bezpieczeństwa. W związku z tym RSA, DSA oraz klucze DH krótsze niż 7680 bitów, a także klucze ECC krótsze niż 384 bity są niedozwolone. Listy parametrów kryptograficznych używających SHA1 do MAC są zabronione. Wersje TLS starsze niż 1.2 są zabronione dla wersji OpenSSL starszych niż 3.0.

    -   poziom 5

        Poziom bezpieczeństwa zapewniający 256 bitów bezpieczeństwa. W związku z tym RSA, DSA oraz klucze DH krótsze niż 15360 bitów, a także klucze ECC krótsze niż 512 bitów są niedozwolone.

    -   domyślnie: 2

    Opcja *securityLevel* jest dostępna począwszy od **OpenSSL 1.1.0**.

-   **requireCert** = yes \| no

    wymagaj certyfikatu klienta dla *verifyChain* lub *verifyPeer*

    Przy opcji *requireCert* ustawionej na *no*, **stunnel** akceptuje połączenia klientów, które nie wysłały certyfikatu.

    Zarówno *verifyChain = yes* jak i *verifyPeer = yes* automatycznie ustawiają *requireCert* na *yes*.

    domyślnie: no

-   **setgid** = IDENTYFIKATOR_GRUPY (tylko Unix)

    identyfikator grupy Unix

    Jako opcja globalna: grupa, z której prawami pracował będzie **stunnel**.

    Jako opcja usługi: grupa gniazda Unix utworzonego przy pomocy opcji \"accept\".

-   **setuid** = IDENTYFIKATOR_UŻYTKOWNIKA (tylko Unix)

    identyfikator użytkownika Unix

    Jako opcja globalna: użytkownik, z którego prawami pracował będzie **stunnel**.

    Jako opcja usługi: właściciel gniazda Unix utworzonego przy pomocy opcji \"accept\".

-   **sessionCacheSize** = LICZBA_POZYCJI_CACHE

    rozmiar pamięci podręcznej sesji TLS

    Parametr określa maksymalną liczbę pozycji wewnętrznej pamięci podręcznej sesji.

    Wartość 0 oznacza brak ograniczenia rozmiaru. Nie jest to zalecane dla systemów produkcyjnych z uwagi na ryzyko ataku DoS przez wyczerpanie pamięci RAM.

-   **sessionCacheTimeout** = LICZBA_SEKUND

    przeterminowanie pamięci podręcznej sesji TLS

    Parametr określa czas w sekundach, po którym sesja TLS zostanie usunięta z pamięci podręcznej.

-   **sessionResume** = yes \| no

    zezwalaj lub nie zezwalaj na wznawianie sesji

    domyślnie: yes

-   **sessiond** = HOST:PORT

    adres sessiond - serwera cache sesji TLS

-   **sni** = NAZWA_USŁUGI:WZORZEC_NAZWY_SERWERA (tryb serwera)

    Użyj usługi jako podrzędnej (virtualnego serwera) dla rozszerzenia TLS Server Name Indication (RFC 3546).

    *NAZWA_USŁUGI* wskazuje usługę nadrzędną, która odbiera połączenia od klientów przy pomocy opcji *accept*. *WZORZEC_NAZWY_SERWERA* wskazuje nazwę serwera wirtualnego. Wzorzec może zaczynać się znakiem '\*', np. '\*.example.com\". Z pojedynczą usługą nadrzędną powiązane jest zwykle wiele usług podrzędnych. Opcja *sni* może być również użyta wielokrotnie w ramach jednej usługi podrzędnej.

    Zarówno usługa nadrzędna jak i podrzędna nie może być skonfigurowana w trybie klienckim.

    Opcja *connect* usługi podrzędnej jest ignorowana w połączeniu z opcją *protocol*, gdyż połączenie do zdalnego serwera jest w tym wypadku nawiązywane przed negocjacją TLS.

    Uwierzytelnienie przy pomocy biblioteki libwrap jest realizowane dwukrotnie: najpierw dla usługi nadrzędnej po odebraniu połączenia TCP, a następnie dla usługi podrzędnej podczas negocjacji TLS.

    Opcja *sni* jest dostępna począwszy od **OpenSSL 1.0.0**.

-   **sni** = NAZWA_SERWERA (tryb klienta)

    Użyj parametru jako wartości rozszerzenia TLS Server Name Indication (RFC 3546).

    Pusta wartość parametru NAZWA_SERWERA wyłącza wysyłanie rozszerzenia SNI.

    Opcja *sni* jest dostępna począwszy od **OpenSSL 1.0.0**.

-   **socket** = a\|l\|r:OPCJA=WARTOŚĆ\[:WARTOŚĆ\]

    ustaw opcję na akceptującym/lokalnym/zdalnym gnieździe

    Dla opcji linger wartości mają postać l_onof:l_linger. Dla opcji time wartości mają postać tv_sec:tv_usec.

    Przykłady:

        socket = l:SO_LINGER=1:60
            ustaw jednominutowe przeterminowanie
            przy zamykaniu lokalnego gniazda
        socket = r:SO_OOBINLINE=yes
            umieść dane pozapasmowe (out-of-band)
            bezpośrednio w strumieniu danych
            wejściowych dla zdalnych gniazd
        socket = a:SO_REUSEADDR=no
            zablokuj ponowne używanie portu
            (domyślnie włączone)
        socket = a:SO_BINDTODEVICE=lo
            przyjmuj połączenia wyłącznie na
            interfejsie zwrotnym (ang. loopback)

-   **sslVersion** = WERSJA_SSL

    wersja protokołu TLS

    Wspierane wersje: all, SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3

    Dostępność konkretnych protokołów zależy od użytej wersji OpenSSL. Starsze wersje OpenSSL nie wspierają TLSv1.1, TLSv1.2, TLSv1.3. Nowsze wersje OpenSSL nie wspierają SSLv2.

    Przestarzałe protokoły SSLv2 i SSLv3 są domyślnie wyłączone.

    Począwszy od **OpenSSL 1.1.0**, ustawienie

        sslVersion = WERSJA_SSL

    jest równoważne opcjom

        sslVersionMax = WERSJA_SSL
        sslVersionMin = WERSJA_SSL

-   **sslVersionMax** = WERSJA_SSL

    maksymalna wspierana wersja protokołu TLS

    Wspierane wersje: all, SSLv3, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3

    *all* włącza wszystkie wersje protokołów aż do maksymalnej wersji wspieranej przez bibliotekę użytej wersji OpenSSL.

    Dostępność konkretnych protokołów zależy od użytej wersji OpenSSL.

    Opcja *sslVersionMax* jest dostępna począwszy od **OpenSSL 1.1.0**.

    domyślnie: all

-   **sslVersionMin** = WERSJA_SSL

    minimalna wspierana wersja protokołu TLS

    Wspierane wersje: all, SSLv3, TLSv1, TLSv1.1, TLSv1.2, TLSv1.3

    *all* włącza wszystkie wersje protokołów aż do minimalnej wersji wspieranej przez bibliotekę użytej wersji OpenSSL.

    Dostępność konkretnych protokołów zależy od użytej wersji OpenSSL.

    Opcja *sslVersionMin* jest dostępna począwszy od **OpenSSL 1.1.0**.

    domyślnie: TLSv1

-   **stack** = LICZBA_BAJTÓW (z wyjątkiem modelu FORK)

    rozmiar stosu procesora tworzonych wątków

    Zbyt duży stos zwiększa zużycie pamięci wirtualnej. Zbyt mały stos może powodować problemy ze stabilnością aplikacji.

    domyślnie: 65536 bytes (wystarczający dla testowanych platform)

-   **ticketKeySecret** = SECRET

    szesnastkowy klucz symetryczny używany przez serwer do zapewnienia poufności biletów sesji

    Bilety sesji zdefiniowane w RFC 5077 zapewniają ulepszoną możliwość wznawiania sesji, w której implementacja serwera nie jest wymagana do utrzymania stanu sesji.

    Łączne użycie opcji *ticketKeySecret* i *ticketMacSecret* umożliwia wznawianie sesji na klastrze serwerów lub wznowienie sesji po restarcie serwera.

    Klucz musi mieć rozmiar 16 lub 32 bajtów, co przekłada się na dokładnie 32 lub 64 cyfry szesnastkowe. Poszczególne bajty mogą być opcjonalnie oddzielone dwukropkami.

    Opcja działa wyłącznie w trybie serwera.

    Opcja *ticketKeySecret* jest dostępna począwszy od **OpenSSL 1.0.0**.

    Wyłączenie opcji *NO_TICKET* jest wymagane dla obsługi biletów sesji w OpenSSL-u starszym niż 1.1.1, ale opcja ta jest niekompatybilna z opcją *redirect*.

-   **ticketMacSecret** = SECRET

    szesnastkowy klucz symetryczny używany przez serwer zapewnienia integralności biletów sesji

    Klucz musi mieć rozmiar 16 lub 32 bajtów, co przekłada się na dokładnie 32 lub 64 cyfry szesnastkowe. Poszczególne bajty mogą być opcjonalnie oddzielone dwukropkami.

    Opcja działa wyłącznie w trybie serwera.

    Opcja *ticketMacSecret* jest dostępna począwszy od **OpenSSL 1.0.0**.

-   **TIMEOUTbusy** = LICZBA_SEKUND

    czas oczekiwania na spodziewane dane

-   **TIMEOUTclose** = LICZBA_SEKUND

    czas oczekiwania na close_notify (ustaw na 0, jeżeli klientem jest MSIE)

-   **TIMEOUTconnect** = LICZBA_SEKUND

    czas oczekiwania na nawiązanie połączenia

-   **TIMEOUTidle** = LICZBA_SEKUND

    maksymalny czas utrzymywania bezczynnego połączenia

-   **TIMEOUTocsp** = LICZBA_SEKUND

    czas oczekiwania na nawiązanie połączenia z serwerem OCSP

-   **transport** = tcp \| udp

    wybór protokołu transportowego

    Wspierane wartości:

    -   *tcp*

        Standardowy TLS po TCP (domyślnie).

    -   *udp*

        DTLS po UDP.

        Każdy datagram otwiera nowe połączenie logiczne w ramach
        usługi.  Serwer używa oddzielnego połączonego gniazda dla
        każdego klienta, a ciasteczka DTLS chronią przed atakami
        DDoS typu refleksyjnego.

    domyślnie: tcp

-   **transparent** = none \| source \| destination \| both (tylko Unix)

    tryb przezroczystego proxy na wspieranych platformach

    Wspierane wartości:

    -   **none**

        Zablokuj wsparcie dla przezroczystego proxy. Jest to wartość domyślna.

    -   **source**

        Przepisz adres, aby nawiązywane połączenie wydawało się pochodzić bezpośrednio od klienta, a nie od programu **stunnel**.

        Opcja jest aktualnie obsługiwana w:

        -   Trybie zdalnym (opcja *connect*) w systemie *Linux \>=2.6.28*

            Konfiguracja wymaga następujących ustawień iptables oraz routingu (na przykład w pliku /etc/rc.local lub analogicznym):

                iptables -t mangle -N DIVERT
                iptables -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
                iptables -t mangle -A DIVERT -j MARK --set-mark 1
                iptables -t mangle -A DIVERT -j ACCEPT
                ip rule add fwmark 1 lookup 100
                ip route add local 0.0.0.0/0 dev lo table 100
                echo 0 >/proc/sys/net/ipv4/conf/lo/rp_filter

            Konfiguracja ta wymaga, aby **stunnel** był wykonywany jako root i bez opcji *setuid*.

        -   Trybie zdalnym (opcja *connect*) w systemie *Linux 2.2.x*

            Konfiguracja ta wymaga skompilowania jądra z opcją *transparent proxy*. Docelowa usługa musi być umieszczona na osobnej maszynie, do której routing kierowany jest poprzez serwer **stunnela**.

            Dodatkowo **stunnel** powinien być wykonywany jako root i bez opcji *setuid*.

        -   Trybie zdalnym (opcja *connect*) w systemie *FreeBSD \>=8.0*

            Konfiguracja ta wymaga skonfigurowania firewalla i routingu. **stunnel** musi być wykonywany jako root i bez opcji *setuid*.

        -   Trybie lokalnym (opcja *exec*)

            Konfiguracja ta jest realizowana przy pomocy biblioteki *libstunnel.so*. Do załadowania biblioteki wykorzystywana jest zmienna środowiskowa \_RLD_LIST na platformie Tru64 lub LD_PRELOAD na innych platformach.

    -   *destination*

        Oryginalny adres docelowy jest używany zamiast opcji *connect*.

        Przykładowa konfiguracja przezroczystego adresu docelowego:

            [transparent]
            client = yes
            accept = <port_stunnela>
            transparent = destination

        Konfiguracja wymaga ustawień iptables, na przykład w pliku /etc/rc.local lub analogicznym.

        W przypadku docelowej usługi umieszczonej na tej samej maszynie:

            /sbin/iptables -t nat -I OUTPUT -p tcp --dport <port_przekierowany> \
                -m ! --uid-owner <identyfikator_użytkownika_stunnela> \
                -j DNAT --to-destination <lokalne_ip>:<lokalny_port>

        W przypadku docelowej usługi umieszczonej na zdalnej maszynie:

            /sbin/iptables -I INPUT -i eth0 -p tcp --dport <port_stunnela> -j ACCEPT
            /sbin/iptables -t nat -I PREROUTING -p tcp --dport <port_przekierowany> \
                -i eth0 -j DNAT --to-destination <lokalne_ip>:<port_stunnela>

        Przezroczysty adres docelowy jest aktualnie wspierany wyłącznie w systemie Linux.

    -   *both*

        Użyj przezroczystego proxy zarówno dla adresu źródłowego jak i docelowego.

    Dla zapewnienia kompatybilności z wcześniejszymi wersjami wspierane są dwie dodatkowe opcje:

    -   *yes*

        Opcja została przemianowana na *source*.

    -   *no*

        Opcja została przemianowana na *none*.

-   **verify** = POZIOM

    weryfikuj certyfikat drugiej strony połączenia

    Opcja ta jest przestarzała i należy ją zastąpić przez opcje *verifyChain* i *verifyPeer*.

    -   *poziom 0*

        zarządaj certyfikatu i zignoruj go

    -   *poziom 1*

        weryfikuj, jeżeli został przedstawiony

    -   *poziom 2*

        weryfikuj z zainstalowanym certyfikatem Centrum Certyfikacji

    -   *poziom 3*

        weryfikuj z lokalnie zainstalowanym certyfikatem drugiej strony

    -   *poziom 4*

        weryfikuj z certyfikatem drugiej strony ignorując łańcuch CA

    -   *domyślnie*

        nie weryfikuj

-   **verifyChain** = yes \| no

    weryfikuj łańcuch certyfikatów drugiej strony

    Do weryfikacji certyfikatu serwera kluczowe jest, aby wymagać również konkretnego certyfikatu przy pomocy *checkHost* lub *checkIP*.

    Samopodpisany certyfikat głównego CA należy umieścić albo w pliku podanym w opcji *CAfile*, albo w katalogu podanym w opcji *CApath*.

    domyślnie: no

-   **verifyPeer** = yes \| no

    weryfikuj certyfikat drugiej strony

    Certyfikat drugiej strony należy umieścić albo w pliku podanym w opcji *CAfile*, albo w katalogu podanym w opcji *CApath*.

    domyślnie: no

# ZWRACANA WARTOŚĆ

**stunnel** zwraca zero w przypadku sukcesu, lub wartość niezerową w przypadku błędu.

# SIGNAŁY

Następujące sygnały mogą być użyte do sterowania programem w systemie Unix:

-   SIGHUP

    Załaduj ponownie plik konfiguracyjny.

    Niektóre globalne opcje nie będą przeładowane:

    -   chroot

    -   foreground

    -   pid

    -   setgid

    -   setuid

    Jeżeli wykorzystywana jest opcja 'setuid' **stunnel** nie będzie mógł załadować ponownie konfiguracji wykorzystującej uprzywilejowane (\<1024) porty.

    Jeżeli wykorzystywana jest opcja 'chroot' **stunnel** będzie szukał wszystkich potrzebnych plików (łącznie z plikiem konfiguracyjnym, certyfikatami, logiem i plikiem pid) wewnątrz katalogu wskazanego przez 'chroot'.

-   SIGUSR1

    Zamknij i otwórz ponownie log. Funkcja ta może zostać użyta w skrypcie rotującym log programu **stunnel**.

-   SIGUSR2

    Zapisz w logu listę aktywnych połączeń.

-   SIGTERM, SIGQUIT, SIGINT

    Zakończ działanie programu.

Skutek wysłania innych sygnałów jest niezdefiniowany.

# PRZYKŁADY

Szyfrowanie połączeń do lokalnego serwera *imapd* można użyć:

    [imapd]
    accept = 993
    exec = /usr/sbin/imapd
    execArgs = imapd

albo w trybie zdalnym:

    [imapd]
    accept = 993
    connect = 143

Aby umożliwić lokalnemu klientowi poczty elektronicznej korzystanie z serwera *imapd* przez TLS należy skonfigurować pobieranie poczty z adresu localhost i portu 119, oraz użyć następującej konfiguracji:

    [imap]
    client = yes
    accept = 143
    connect = serwer:993

W połączeniu z programem *pppd* **stunnel** pozwala zestawić prosty VPN. Po stronie serwera nasłuchującego na porcie 2020 jego konfiguracja może wyglądać następująco:

    [vpn]
    accept = 2020
    exec = /usr/sbin/pppd
    execArgs = pppd local
    pty = yes

Poniższy plik konfiguracyjny może być wykorzystany do uruchomienia programu **stunnel** w trybie *inetd*. Warto zauważyć, że w pliku konfiguracyjnym nie ma sekcji *\[nazwa_usługi\]*.

    exec = /usr/sbin/imapd
    execArgs = imapd

Aby skonfigurować VPN można użyć następującej konfiguracji klienta:

    [socks_client]
    client = yes
    accept = 127.0.0.1:1080
    connect = vpn_server:9080
    verifyPeer = yes
    CAfile = stunnel.pem

Odpowiadająca jej konfiguracja serwera vpn_server:

    [socks_server]
    protocol = socks
    accept = 9080
    cert = stunnel.pem
    key = stunnel.key

Do przetestowania konfiguracji można wydać na maszynie klienckiej komendę:

    curl --socks4a localhost http://www.example.com/

Przykładowa konfiguracja serwera SNI:

    [virtual]
    ; usługa nadrzędna
    accept = 443
    cert =  default.pem
    connect = default.internal.mydomain.com:8080

    [sni1]
    ; usługa podrzędna 1
    sni = virtual:server1.mydomain.com
    cert = server1.pem
    connect = server1.internal.mydomain.com:8081

    [sni2]
    ; usługa podrzędna 2
    sni = virtual:server2.mydomain.com
    cert = server2.pem
    connect = server2.internal.mydomain.com:8082
    verifyPeer = yes
    CAfile = server2-allowed-clients.pem

Przykładowa konfiguracja umożliwiająca uwierzytelnienie z użyciem klucza prywatnego przechowywanego w Windows Certificate Store (tylko Windows):

    engine = capi

    [service]
    engineId = capi
    client = yes
    accept = 127.0.0.1:8080
    connect = example.com:8443

W przypadku użycia silnika CAPI, nie należy ustawiać opcji cert, gdyż klucz klienta zostanie automatycznie pobrany z Certificate Store na podstawie zaufanych certyfikatów CA przedstawionych przez serwer.

Przykładowa konfiguracja umożliwiająca użycie certyfikatu i klucza prywatnego z urządzenia obsługiwanego przez silnik pkcs11:

    engine = pkcs11
    engineCtrl = MODULE_PATH:opensc-pkcs11.so
    engineCtrl = PIN:123456

    [service]
    engineId = pkcs11
    client = yes
    accept = 127.0.0.1:8080
    connect = example.com:843
    cert = pkcs11:token=MyToken;object=MyCert
    key = pkcs11:token=MyToken;object=MyKey

Przykładowa konfiguracja umożliwiająca użycie certyfikatu i klucza prywatnego umieszczonego na tokenie SoftHSM:

    engine = pkcs11
    engineCtrl = MODULE_PATH:softhsm2.dll
    engineCtrl = PIN:12345

    [service]
    engineId = pkcs11
    client = yes
    accept = 127.0.0.1:8080
    connect = example.com:843
    cert = pkcs11:token=MyToken;object=KeyCert

Przykładowa konfiguracja umożliwiająca użycie certyfikatu i klucza prywatnego z urządzenia obsługiwanego przez provider \`pkcs11prov\`:

Uwaga: wymaga OpenSSL 3.0 lub nowszego

    setEnv = PKCS11_MODULE_PATH=opensc-pkcs11.dll
    setEnv = PKCS11_PIN:123456
    provider = pkcs11prov

    [service]
    client = yes
    accept = 127.0.0.1:8080
    connect = example.com:843
    cert = pkcs11:token=MyToken;object=MyCert
    key = pkcs11:token=MyToken;object=MyKey

Uwaga: wymaga OpenSSL 3.5 lub nowszego

    provider = pkcs11prov
    providerParameter = pkcs11prov:pkcs11_module=opensc-pkcs11.dll
    providerParameter = pkcs11prov:pin=123456

    [service]
    client = yes
    accept = 127.0.0.1:8080
    connect = example.com:843
    cert = pkcs11:token=MyToken;object=MyCert
    key = pkcs11:token=MyToken;object=MyKey

W systemie Windows biblioteka PKCS#11 musi znajdować się w katalogu \`ossl-modules\`, lub należy podać jej pełną ścieżkę bezwzględną w \`PKCS11_MODULE_PATH\` lub parametrze \`pkcs11_module\`.

# NOTKI

## OGRANICZENIA

**stunnel** nie może być używany do szyfrowania protokołu *FTP*, ponieważ do przesyłania poszczególnych plików używa on dodatkowych połączeń otwieranych na portach o dynamicznie przydzielanych numerach. Istnieją jednak specjalne wersje klientów i serwerów FTP pozwalające na szyfrowanie przesyłanych danych przy pomocy protokołu *TLS*.

## TRYB INETD (tylko Unix)

W większości zastosowań **stunnel** samodzielnie nasłuchuje na porcie podanym w pliku konfiguracyjnym i tworzy połączenie z innym portem podanym w opcji *connect* lub nowym programem podanym w opcji *exec*. Niektórzy wolą jednak wykorzystywać oddzielny program, który odbiera połączenia, po czym uruchamia program **stunnel**. Przykładami takich programów są inetd, xinetd i tcpserver.

Przykładowa linia pliku /etc/inetd.conf może wyglądać tak:

    imaps stream tcp nowait root @bindir@/stunnel
        stunnel @sysconfdir@/stunnel/imaps.conf

Ponieważ w takich przypadkach połączenie na zdefiniowanym porcie (tutaj *imaps*) nawiązuje osobny program (tutaj *inetd*), **stunnel** nie może używać opcji *accept*. W pliku konfiguracyjnym nie może być również zdefiniowana żadna usługa (*\[nazwa_usługi\]*), ponieważ konfiguracja taka pozwala na nawiązanie tylko jednego połączenia. Wszystkie *OPCJE USŁUG* powinny być umieszczone razem z opcjami globalnymi. Przykład takiej konfiguracji znajduje się w sekcji *PRZYKŁADY*.

## CERTYFIKATY

Protokół TLS wymaga, aby każdy serwer przedstawiał się nawiązującemu połączenie klientowi prawidłowym certyfikatem X.509. Potwierdzenie tożsamości serwera polega na wykazaniu, że posiada on odpowiadający certyfikatowi klucz prywatny. Najprostszą metodą uzyskania certyfikatu jest wygenerowanie go przy pomocy wolnego pakietu **OpenSSL**. Więcej informacji na temat generowania certyfikatów można znaleźć na umieszczonych poniżej stronach.

Plik *.pem* powinien zawierać klucz prywatny oraz podpisany certyfikat (nie żądanie certyfikatu). Otrzymany plik powinien mieć następującą postać:

    -----BEGIN RSA PRIVATE KEY-----
    [zakodowany klucz]
    -----END RSA PRIVATE KEY-----
    -----BEGIN CERTIFICATE-----
    [zakodowany certyfikat]
    -----END CERTIFICATE-----

## LOSOWOŚĆ

**stunnel** potrzebuje zainicjować PRNG (generator liczb pseudolosowych), gdyż protokół TLS wymaga do bezpieczeństwa kryptograficznego źródła dobrej losowości. Następujące źródła są kolejno odczytywane aż do uzyskania wystarczającej ilości entropii:

-   Zawartość pliku podanego w opcji *RNDfile*.

-   Zawartość pliku o nazwie określonej przez zmienną środowiskową RANDFILE, o ile jest ona ustawiona.

-   Plik .rnd umieszczony w katalogu domowym użytkownika, jeżeli zmienna RANDFILE nie jest ustawiona.

-   Plik podany w opcji '\--with-random' w czasie konfiguracji programu.

-   Zawartość ekranu w systemie Windows.

-   Gniazdo egd, jeżeli użyta została opcja *EGD*.

-   Gniazdo egd podane w opcji '\--with-egd-socket' w czasie konfiguracji programu.

-   Urządzenie /dev/urandom.

Warto zwrócić uwagę, że na maszynach z systemem Windows, na których konsoli nie pracuje użytkownik, zawartość ekranu nie jest wystarczająco zmienna, aby zainicjować PRNG. W takim przypadku do zainicjowania generatora należy użyć opcji *RNDfile*.

Plik *RNDfile* powinien zawierać dane losowe \-- również w tym sensie, że powinny być one inne przy każdym uruchomieniu programu **stunnel**. O ile nie użyta została opcja *RNDoverwrite* jest to robione automatycznie. Do ręcznego uzyskania takiego pliku użyteczna może być komenda *openssl rand* dostarczana ze współczesnymi wersjami pakietu **OpenSSL**.

Jeszcze jedna istotna informacja \-- jeżeli dostępne jest urządzenie */dev/urandom* biblioteka **OpenSSL** ma zwyczaj zasilania nim PRNG w trakcie sprawdzania stanu generatora. W systemach z */dev/urandom* urządzenie to będzie najprawdopodobniej użyte, pomimo że znajduje się na samym końcu powyższej listy. Jest to właściwość biblioteki **OpenSSL**, a nie programu **stunnel**.

## PARAMETRY DH

Począwszy od wersji 4.40 **stunnel** zawiera w kodzie programu 2048-bitowe parametry DH. Od wersji 5.18 te początkowe wartości parametrów DH są wymieniane na automatycznie generowane parametry tymczasowe. Wygenerowanie parametrów DH może zająć nawet wiele minut.

Alternatywnie parametry DH można umieścić w pliku razem z certyfikatem, co wyłącza generowanie parametrów tymczasowych:

    openssl dhparam 2048 >> stunnel.pem

# PLIKI

-   *\@sysconfdir@/stunnel/stunnel.conf*

    plik konfiguracyjny programu

# BŁĘDY

Opcja *execArgs* oraz linia komend Win32 nie obsługuje cytowania.

# ZOBACZ RÓWNIEŻ

-   <https://www.stunnel.org/>

    aplikacja **stunnel**

-   <https://openssl-library.org/>

    biblioteka **OpenSSL**

# AUTOR

-   Michał Trojnara

    <Michal.Trojnara@stunnel.org>
