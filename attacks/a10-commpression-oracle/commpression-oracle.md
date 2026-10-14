# Compression Oracle 

Możliwość wnioskowania o zawartości plaintextu z rozmiaru ciphertextu bez znajomości klucza

**Typ ataku:** Compression Oracle Attack

**Źródło:** [„SoK: Why Johnny Can't Fix PGP Standardization"](https://arxiv.org/pdf/2008.06913)

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

API różnych rozwiązań szyfruje każde żądanie zawierające token sesji użytkownika za pomocą pgp. Atakujący może wstrzyknąć dowolny fragment tekstu do plaintextu (np. przez pole formularza, parametr URL, komentarz), a następnie obserwować wyłącznie rozmiar zaszyfrowanego pliku wynikowego, nie ma on dostępu do klucza prywatnego ani plaintextu. Celem ataku jest odgadnięcie zawartego w zaszyfrowanym pliku tokenu.

### Realizacja ataku dla pgp

Realizowany scenriusz ataku w tym przykładzie będzie na zasadzie API archiwum logów z piplinu CI/CD. System archiwizuje logi procesów CI/CD zaszyfrowane za pomocą pgp. Logi te zawierają tokeny sesji użytkowników tworzących pipliny. Atakujący może wstrzyknąć dowolny tekst do logów (np. przez pole "imię użytkownika" w zapytaniu np: imię: eyJhbGciOiJIUzI1NiJ9.SECRET). Następnie obserwuje rozmiar pliku.

W tej symulacji za działanie serwera posłuży funkcja w pythonie szyfrująca wiadomość z dodanym elementem i zwracającą jedynie wielkość zaszyforwanego pliku:

```python
def encrypt_size(injected_prefix):
    plaintext = (
        f"Daily Build\n"
        f"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.SECRET_TOKEN_ABCDEF\n"
        f"{injected_prefix}\n"
    )
    proc = subprocess.run(
        ["gpg", "--symmetric", "--cipher-algo", "AES256",
         "--compress-algo", "ZIP", "--allow-old-cipher-algos",
         "--batch", "--passphrase", "haslo1234", "--output", "-"],
        input=plaintext.encode(), capture_output=True
    )
    return len(proc.stdout)
```

Następnie atakujący sprawdza wielkość pliku bez żadnych modyfikacji i patrzy jak zmienia się długość szyfrowanego pliku po dodaniu kolejnych znaków. Wybiera taką modyfikację która wprowadziła najmniejszą zmianę w długości zaszyfrowanej wiadomości i w ten sposób odgaduje token. Proces zgadywania odbywa się do moemntu kiedy modyfikacje nie zmieniają wielkości pliku o wiecej niż jeden znak (2B z uwagi na kodowanie UTF-16):

```
…/docs/atack-vectors master ? ❯ python3 pgp_cracker.py
Rozmiar ciphertextu bez wstrzyknięcia: 146B
        Pozycja 1: 'S' (148B) | zgadnięto: 'S'
        Pozycja 2: 'E' (148B) | zgadnięto: 'SE'
        Pozycja 3: 'C' (148B) | zgadnięto: 'SEC'
        Pozycja 4: 'R' (148B) | zgadnięto: 'SECR'
        Pozycja 5: 'E' (148B) | zgadnięto: 'SECRE'
        Pozycja 6: 'T' (148B) | zgadnięto: 'SECRET'
        Pozycja 7: '_' (148B) | zgadnięto: 'SECRET_'
        Pozycja 8: 'T' (148B) | zgadnięto: 'SECRET_T'
        Pozycja 9: 'O' (148B) | zgadnięto: 'SECRET_TO'
        Pozycja 10: 'K' (148B) | zgadnięto: 'SECRET_TOK'
        Pozycja 11: 'E' (148B) | zgadnięto: 'SECRET_TOKE'
        Pozycja 12: 'N' (148B) | zgadnięto: 'SECRET_TOKEN'
        Pozycja 13: '_' (148B) | zgadnięto: 'SECRET_TOKEN_'
        Pozycja 14: 'A' (148B) | zgadnięto: 'SECRET_TOKEN_A'
        Pozycja 15: 'B' (148B) | zgadnięto: 'SECRET_TOKEN_AB'
        Pozycja 16: 'C' (148B) | zgadnięto: 'SECRET_TOKEN_ABC'
        Pozycja 17: 'D' (148B) | zgadnięto: 'SECRET_TOKEN_ABCD'
        Pozycja 18: 'E' (148B) | zgadnięto: 'SECRET_TOKEN_ABCDE'
        Pozycja 19: 'F' (147B) | zgadnięto: 'SECRET_TOKEN_ABCDEF'
```

Jak widać udało się prawidłowo określić tajny token użytkownika jedynie za pomocą porównywania wielkości szyfrowanego pliku.


### Realizacja ataku dla age

Podobnie jak w przypadku pgp prubujemy modyfikować szyfrowany tekst i na podstawie zmian w wielkości zgadywać sekretny token.

Ponownie mamy funkcje odpowiedzialną za symulację pracy serwera:
```python
def age_encrypt_size(injected_prefix):
    plaintext = (
        f"Daily Build\n"
        f"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.SECRET_TOKEN_ABCDEF\n"
        f"{injected_prefix}\n"
    )
    proc = subprocess.run(
        ["age", "-r", AGE_PUB_KEY, "-o", "-"],
        input=plaintext.encode(), capture_output=True
    )
    return len(proc.stdout)
```

I tak jak w przypadku pgp doklejamy do oryginalnej wiadomości kolejne znaki i patrzymy kktóra modyfikacja wpłyneła na rozmiar szyfrowanej wiadomości w najmniuejszym stopniu:

```
…/docs/atack-vectors master ? ❯ python3 age_crack.py
Rozmiar ciphertextu bez wstrzyknięcia: 276B
        Pozycja 1: min=298B max=298B delta=0B
        Pozycja 2: min=298B max=298B delta=0B
        Pozycja 3: min=298B max=298B delta=0B
        Pozycja 4: min=298B max=298B delta=0B
```

Jak widać dowolna zmiana wpływa na szyfrowaną wiadomość w takim samym stopniu wiec atakujący nie może w żaden sposób wyciągać wniosków z otrzymanych wielkości szyfru.

## Wnioski

Dokumentacja pgp zaznacza `penPGP implementations SHOULD compress the message after applying the signature but before encryption.` zatem kompresja odbywa się zawsze przed konaniem ekrypcji.

Kompresja ZIP działa przez eliminację powtarzających się sekwencji. Jeśli atakujący wstrzyknie fragment pasuje do sekretnego fragmentu już obecnego w dokumencie, kompresja działa lepiej zatem wynik jest krótszy co za tym idzie ciphertext jest krótszy. Ponieważ szyfr AES-CFB nie ukrywa rozmiaru plaintextu, różnica długości ciphertextu jest bezpośrednio widoczna, a atak możliwy.

age nie ma takich problemów, ponieważ kompresja nie istnieje w specyfikacji. Jeśli użytkownik chce zastosować kompresję, powinien skompresować plik przed wywołaniem age, co jest bezpieczne, bo wtedy nie ma zagrożenia ze strny ataku typu oracle.
