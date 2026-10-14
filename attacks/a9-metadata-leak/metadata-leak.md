# Metadata Leak

Ujawnienie tożsamości odbircy zaszyfrowanego pliku

**Typ ataku:** Traffic Analysis, Passive Attack, Privacy Attack

**Źródło:** [„Reducing Metadata Leakage from Encrypted Files and Communication with PURBs"](https://arxiv.org/pdf/1806.03160)

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

Atakujący przechwytuje zaszyfrowany plik nie posaida żadnego klucza prywantego mając za to dostęp do kluczy prywatnych np. w ramach organizacji. Atakujący próbuje jedoznacznie określić kto jest odbiorcą waidomości.

### Realizacja ataku dla pgp

Przygotowanie przed realizacją ataku. Generowanie klucza osoby do której wiadomość bedzie wysyłana:

```
…/docs/atack-vectors master ? ❯ gpg --pinentry-mode loopback --batch --gen-key <<'EOF'
Key-Type: RSA
Key-Length: 2048
Subkey-Type: RSA
Subkey-Length: 2048
Name-Real: Alicja Karp
Name-Email: alicja@example.com
Expire-Date: 0
Passphrase: test1234
%commit
EOF
gpg: certyfikat unieważnienia został zapisany jako „/home/karas/.gnupg/openpgp-revocs.d/6BC5613D12E89DFDC59B8DD1E7C05AB326F3AF99.rev”
```
Utworzenie tajnego dokumentu:

```
…/docs/atack-vectors master ? ❯ echo "TAJNY RAPORT FINANSOWY Q1 2026
Przychody: 4.2M PLN
Marża: 23%
Odbiorca: Alicja Kowalska" > tajny_dokument.txt
```
Zaszyfrowanie dokumentu z oznaczeniem że odbiorcą będzie osoba z ceryfikatem posiadającym mail `alicja@example.com`:
```
…/docs/atack-vectors master ? ❯ gpg --trust-model always --encrypt --recipient alicja@example.com --output tajny_dokument.gpg tajny_dokument.txt
```
Zaszyfrowany plik zostaje przechwycony przez atakującego, który mimo braku hasła może przeprowadzić analizę zaszyfrowanego pliku:

```
…/Magisterka/openPGP ✗ gpg --list-packets tajny_dokument.gpg
gpg: zaszyfrowano kluczem RSA o identyfikatorze 64FA0EDE0C94B3A6
gpg: błąd odszyfrowywania kluczem publicznym: Brak klucza tajnego
gpg: błąd odszyfrowywania: Brak klucza tajnego
# off=0 ctb=85 tag=1 hlen=3 plen=268
:pubkey enc packet: version 3, algo 1, keyid 64FA0EDE0C94B3A6
        data: [2047 bits]
# off=271 ctb=d2 tag=18 hlen=2 plen=165 new-ctb
:encrypted data packet:
        length: 165
        mdc_method: 2
```
Jak widać nie udaj się odszyfrować pliku ale możemy odczytać część idetyfikatora odbiorcy przechowywanego w plaintexcie: `keyid 64FA0EDE0C94B3A6`.

W przypadku przechowywania keychaina z publicznymi kluczami na serwerze firmowym (z racji, że klucze publiczne powinny być ogólno dostępne) atakujący może dokładnie określić osbiorece wiadomości:

```
…/docs/atack-vectors master ? ✗ gpg --list-keys --keyid-format long
gpg: sprawdzanie bazy zaufania
gpg: marginals needed: 3  completes needed: 1  trust model: pgp
gpg: poziom: 0 poprawnych:   3 podpisanych:   0 zaufanie: 0-,0q,0n,0m,0f,3u
[keyboxd]
---------
pub   rsa2048/E7C05AB326F3AF99 2026-05-31 [SCEAR]
      6BC5613D12E89DFDC59B8DD1E7C05AB326F3AF99
uid          [   absolutne   ] Alicja Karp <alicja@example.com>
sub   rsa2048/64FA0EDE0C94B3A6 2026-05-31 [SEA]

pub   nistp256/DCD119072AB543CA 2026-05-21 [SC]
      A635B91EBFB36B57CE05E3B7DCD119072AB543CA
uid          [    nieznane   ] Pico Device <pico@device>
sub   nistp256/AE2B644908704486 2026-05-21 [E]

pub   nistp256/00E0CDBC3E33B318 2026-05-20 [SC]
      D191400F5E015E35A4FD61E300E0CDBC3E33B318
uid          [   absolutne   ] Debug Key <debug@test.com>
sub   nistp256/1B6333FBC4273295 2026-05-20 [E]

pub   nistp256/787802B695E94B24 2026-05-07 [SC]
      FEB8E1D11FA0FD755B79C17F787802B695E94B24
uid          [   absolutne   ] Test Key <test@example.com>
sub   nistp256/0B1465C099B78C7F 2026-05-07 [E]
```

Widać, że uzyskany przez atakującego podczas analizy zaszyfrowanego pliku `keyid 64FA0EDE0C94B3A6` jest taki sam jak subkey Alicji Karp `sub   rsa2048/64FA0EDE0C94B3A6 2026-05-31 [SEA]`. Zatem atakujący ustalił jednoznacznie, że odbiorcą pliku jest Alicja Karp z mailem `alicja@example.com`, bez znajomości klucza prywatnego oraz bez łamania szyfrowania.

### Realizacja ataku dla age

Generujemy klucz publiczny dla adresata wiadomości:

```
…/docs/atack-vectors master ? ❯ age-keygen -o alicja_age.key
Public key: age18ujjc3ahxhc29wuerz8p9yu8039txpurls6pkdsgvg99ahzrsdyq462a6d
```

Szyfrujemy wiadomość za pomocą age:

```
…/docs/atack-vectors master ? ❯ age -r age18ujjc3ahxhc29wuerz8p9yu8039txpurls6pkdsgvg99ahzrsdyq462a6d -o tajny_dokument.age tajny_dokument.txt
```
Ponownie zaszyfrowany plik zostaje przechwycony przez atakującego, który przeprowadza analizę zaszyfrowanego pliku:

```
…/Magisterka/age ❯ strings tajny_dokument.age
age-encryption.org/v1
-> X25519 uS4vvTckdMafkQVRakDTh8KtXGTP2yeAl6ExTTjMWQ0
zc5nuvVuJoJFdX5wgywCchIvQHB7/U70AivpmlXvPcE
--- SbFlsQjN4HUBpnmYHEqiH3xNlwQuNsDd7NohlYTzfzQ
dx@"
```

Jak widać heder pliku (stanza) zawiera informacje o wersji formatu, typie stanzy oraz efemerycznym kluczu publiczny wygenerowany tylko dla tego pliku. Ten klucz nie istnieje w żadnej bazie kluczy, nie identyfikuje odbiorcy, nie można go powiązać z kluczem publicznym Alicji Karp bez jej klucza prywatnego. 

## Wnioski

pgp umożliwia mitygację tej luki w ukrywaniu tożsamości odbiorcy za pomocą użycia tagu `--hidden-recipient` który wprowadza "wildcard" `keyid 0000000000000000` w miejscu keyid użytkownika. Jednak nie jest to domyślne zachowanie GnuPG, co za tym idzie większość użytkowników i aplikacji nie używa tej opcji.

Podatność PGP jest architektoniczna nie można jej usunąć bez złamania kompatybilności wstecznej, ponieważ wszystkie istniejące pliki `.gpg` przestałyby być deszyfrowane bez Key ID.

Odporność age wynika ze zastosowania HKDF wraz z efemerycznymi kluczami X25519, eliminują tę klasę ataków z definicji.