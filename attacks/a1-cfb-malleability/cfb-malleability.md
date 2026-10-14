# CFB Malleability 

Modyfikacja bajtu ciphertextu daje kontrolowaną zmianę plaintextu bez znajomości klucza

**Typ ataku:** Malleable Encryption

**Źródło:** [„Efail"](https://efail.de/)

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

Atakujący posiadający zaszyfrowany plik może go bez odszyfrowaynia zmodyfikować aby po jego odszyfrowaniu odbiorca widział inną zawartość niż ta która była szyfrowana.


### Realizacja ataku dla pgp

Przed rozpoczęciem ataku szyfrujemy wiadomość za pomocą pgp:

```
gpg --symmetric --rfc2440 --cipher-algo AES256 --compress-algo none --allow-old-cipher-algos --batch --passphrase "demo" --output target.gpg plaintext_efail.txt
```

Opcja `--passphrase` jest tu wykorzystana w ramach demostracji jako uproszczenie, atak działa by również gdyby plik był szyfrowany za pomocą klucza publicznego.

Warto zauważyć, że przy zastosowaniu takich flag gpg informuje użytkownika o niebezpieczeństwie związane z użyciem takich opcji:

```
gpg: OSTRZEŻENIE: szyfrowanie bez ochrony przed manipulacją jest niebezpieczne
gpg: Podpowiedź: nie używać opcji --rfc2440
```

ale dalej użytkownik może to zrobić a komunikat z ostrzeżeniem nie jest widoczny jeżeli np szyfrowanie następuje za pomocą skryptu.

Po przechwyceniu takiej wiadomości atakujący może zmodyfikować wartości bitowe zaszyfrowanej wiadomości. Gdy odbiorca otrzyma wiadomość od atakującego będzie mógł ją odczytać mimo moidyfikacji. pgp zwróci kod 2 jest to jednak traktowane jako ostrzeżenie nie błąd. 

I tak wiadomość:
```
TAJNY DOKUMENT FINANSOWY
Przelew: 50000 PLN
Konto docelowe: PL61109010140000071219812874
Autoryzacja: CONFIRMED
```
po modyfikacji 50 bitu w cyphertexcie wygląda następująco po odszyfrowaniu:
```
��~I DOKUMENT FINANSOWY
Przelew: 50000 PLN
Konto docelowe: PL61109010140000071219812874
Autoryzacja: CONFIRMED
``` 

Co ważne przy odszyfrowaniu pliku w terminalu gpg ostrzega nas że plik mógł być zmodyfikowany:

```
gpg: OSTRZEŻENIE: wiadomość nie była zabezpieczona przed manipulacją
gpg: wymuszono błąd odszyfrowywania!
```


### Realizacja ataku dla age

Dla age w pierwszym kroku generujemy klucz oraz z jego pomocą szyfrujemy plik:

```
…/docs/atack-vectors master ? ❯ age-keygen -o age.key
Public key: age15ln6vvk4rn5shvl2tddv0t8mwgy37tj2ez4qdrwz3vr224qtx92qn3en23

…/docs/atack-vectors master ? ❯ age -r $(age-keygen -y age.key) -o target.age plaintext_efail.txt
```

Tu ponownie modyfikujemy bity w cyphertexcie i próbójemy odszyfrować tak zmieniony plik. age zwraca kod błedu 1, odmowy odszyfrowania, z komunikatem `age: error: no identity matched any of the recipients`. Dodatkowo na wyjściu nie jest nic zwracane.

## Wnioski

Zaprezentowany przykłąd CFB malleability dla pgp jedynie może zniekształcać wiadomość i powodować zniszczenie jej treści ale w 2018 roku EFail pokazał jak ta właściwość kryptograficzna, połączona z podatnością klientów pocztowych (renderowanie HTML + ignorowanie exit code), dała atakującemu pełny dostęp do plaintextu bez łamania szyfrowania. Do tamtego czasu klienty pocztowe zostały zaktualizowane ale podatność na CFB malleability pozostaje niezmieniony w pgp.

Podatność na CFB malleability jest podatnością architektoniczną, nie implementacyjną. Oznacza to, że nie można jej naprawić bez zmiany specyfikacji i złamania kompatybilności wstecznej. Dlatego mimo ostrzeżeń cały czas jest możliwe szyfrowanie plików w tym trybie.

age używa ChaCha20-Poly1305 (AEAD), który jest z definicji IND-CCA2 bezpieczny. Każda modyfikacja ciphertextu powoduje weryfikację tagu Poly1305, która zawsze kończy się odmową zwrócenia plaintextu.