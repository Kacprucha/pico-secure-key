# Parser attack surface

Złożoność parsera OpenPGP w porównaniu z age

**Typ ataku:** Memory Corruption, Logic Error, Parser Attack

**Źródło:** [„CVE-2025-47934 Detail"](https://nvd.nist.gov/vuln/detail/CVE-2025-47934), ["Re: What’s Up Johnny? Covert Content Attacks on Email End-to-End Encryption"](https://arxiv.org/pdf/1904.07550)

## Dane techniczne

Wersja gpg: 
```
…/docs/atack-vectors master ? ❯ gpg --version
gpg (GnuPG) 2.4.9
```
Wersja age:
```
…/docs/atack-vectors master ? ✗ age --version
1.3.1
```

## Scenariusz ataku

Opisane w tym dokumencie porównanie paresrów obu protokołów nie ma na celu przedstawienie konkretnego ataku tylko pokazanie wielkość powierzchni ataków i odporności parserów na zdeformowane wejście. Porównianie skupi się na pokazaniu różnic w złożoności paresrów dla obu formatów szyfrowania plików, przeprowadzenie fuzz testu dla zaszyfrowanych plików oboma protokołami oraz pokzaniu anomali, które wynikają ze złożoności parsera (partial body lengths, kompresja w kompresji). 


### Realizacja ataku dla pgp

Zacznijmy od przyjrzenia się jak może być złożony zaszyfrowany plik pgp. pgp daje do dyspozycji użytkownikowi 17 pakietów standardowych oraz 4 prywatne, ma do dyspozycji 2 formaty nagłówków, umożliwia zagniedżanie pakietów oraz umożliwia stosowanie nagłóweków Partial Body Length. Złożoność pliku najlepiej oddaje plik przechowujący logikę parsowania w OpenPGP (`g10/parse-packet.c`), który ma ponad 4000 linii.

Złożoność parsowania możemy przetestować też za pomocą fuzz testu. Test zostałprzeprowadzony poprzez mutacje każdego offset z każdy bitem wraz z obcięciem na każdej długości. Udało się zidetyfikować 3651 unikatowych błędów z których można wyróżnić 11 typów błędów. Co daje nam 10 gałęzi błędów.

Przejdźmy teraz do analizy zagrożenia wynikającego z partial body length. Aby to pokazać został wzięty plik o długości 546B i podany obróbce aby uzyskać jedne plik o pakietach `off=0 ctb=cb tag=11 hlen=3 plen=552 new-ctb` oraz drugi o pakietach `off=0 ctb=cb tag=11 hlen=2 plen=0 partial new-ctb`. Ekstrakcja treści (`gpg -d`) z obu kodowań zwróciła bajtowo identyczne 546B. Dwa różne ciągi bajtów ekstrahują się do tej samej treści, format OpenPGP nie ma kanonicznej reprezentacji pakietu. Parser musi obsługiwać wiele kodowań tej samej treści, co jest źródłem rozbieżności między implementacjami. Powoduje to rozjazd między widokiem pakietów dla weryfikacji podpisu a widokiem dla ekstrakcji danych co może pozwalić na obejście weryfikacji podpisu.

Ostatnią płaszczyzna ataku jaka została przenalizowana to możliwość kompresji jaką daje pgp. `gpg --list-packets` w pełni dekompresuje pakiet w trakcie samego parsowania, parser realizuje dekompresję, więc atak na zasoby jest możliwy już na etapie listowania pakietów. Zagnieżdżanie Compressed-in-Compressed pozwala mnożyć współczynnik kaskadowo, współczynnik ten zależy od kompresowalności treści (dla zwielokrotnionego tekstu wyniósł on 410.3).

### Realizacja ataku dla age

Przeanalizujmy teraz jak złożony jest plik age. age oferuje 1 typ pakietów, 1 format nagłówka, nie umożliwia zagniedżania pakietów, ani nie umożliwia nagłówków Partial Body Length. Jak widać format nie jest zbytnio złożony ponownie można to podkreślić pokazując wielkością pliku służącego do parsowania w age `internal/format/format.go`, który ma jedynie ponad 300 linii.

Ponownie przeprowadzamy fuzz test tak jak w przypadku pgp. Tym razem udało się wyróżnić 6 unikalnych sygnatur błédów zatem mamy doczynienia z 5 gałęziami błędów. Jest to o połowę mniej niż w przypadku pgp.

Analizy nagłówków Partial Body Length oraz analizy zagnieżdżań Compressed-in-Compressed nie możemy wykonać dla age ponieważ ten protokól nie oferuje takowych możlwiści.

## Wnioski

Format pgp ma wielokrotnie większą powierzchnię ataku parsera: 2 formaty nagłówka, 7+ ścieżek długości, 17 typów pakietów, partial body lengths i zagnieżdżanie. Każdy dodatkowy typ pakietu, format nagłówka i ścieżka długości to osobna gałąź logiki parsera co za tym idzie osobna potencjalna powierzchnia błędu. Minimalistyczne podejście age pozwala na zminiejszenie płaszczyzny ataków. Differential fuzzing pokazuje większą liczbę gałęzi błędu parsera pgp (10 do 5). Każda gałąź to osobny fragment logiki podatny na błędy implementacji, co za tym idzie stosując pgp jesteśmy 2 razy bardziej wystawieni na zagrożenie ataku. Ddatkowo pgp dopuszcza niekanoniczne kodowanie (ta sama treść, różne bajty, bajtowo identyczna ekstrakcja) oraz amplifikację przez kompresję, których problematyczność age w ogóle nie dotyczy ponieważ nie są one w żaden sposób zaimplementowane. Złożoność pgp jest nieusuwalna bez złamania kompatybilności wstecznej.


