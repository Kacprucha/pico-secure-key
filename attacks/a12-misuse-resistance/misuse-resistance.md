# Misuse resistance

Możliwość błędnej konfiguracji oraz rozluźnienie kryptograficzne

**Typ ataku:** Misconfiguration, Cryptographic Agility Attack

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

pgp pozwala użytkownikowi wybrać dowolny zarejestrowany algorytm, w tym algorytmy kryptograficznie złamane lub przestarzałe, bez generowania błędu. Oznacza to, że błędna konfiguracja lub celowa degradacja przez atakującego (np. w skrypcie CI/CD) może cicho obniżyć bezpieczeństwo wszystkich szyfrowanych plików.

### Realizacja ataku dla pgp

Przygotowanie przed realizacją ataku. Generowanie klucza którym będziemy szyfrować pliki:

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

Domyślnie bezpieczne szyfrowanie są za pomocą AES-256 w trybie pracy CFB `gpg: dane zaszyfrowano za pomocą AES256.CFB`

Możemy jednak modyfikować typ używanego algorytmu szyfrowania za pomocą flagi `--cipher-algo` oraz `--allow-old-cipher-algos`:

```
gpg --trust-model always  --encrypt  --recipient alicja@example.com --cipher-algo 3DES --allow-old-cipher-algos  --output degraded_3des.gpg tajny_dokument.txt
```
Po inspekcji zaszyfrowanego pliku można zobaczyć że tym razem jest on zaszyfrowany algorytmem 3DES w trybie pracy CFB `gpg: dane zaszyfrowano za pomocą 3DES.CFB`.

pgp umożliwia również degradacje funkcji hashującej używanej do przechowywania klucza na SHA-1:

```
…/docs/atack-vectors master ? ✗ echo "Tajny tekst" | gpg --symmetric --cipher-algo AES256 --s2k-digest-algo SHA1 --allow-old-cipher-algos --batch --passphrase test1234  --output degraded_sha1kdf.gpg
```

W trakcie inspekcji pliku możemy odczytać:

```
:symkey enc packet: version 4, cipher 9, aead 0, s2k 3, hash 2
        salt 2254E22B47951FA4, count 65011712 (255)
```
Jest to niebezpieczne z racji na fakt, że SHA-1 jest kryptograficznie złamana ([SHAttered 2017](https://www.microsoft.com/en-us/msrc/blog/2017/02/sha-1-collisions-research)).

pgp umożliwia ustawianie wielu innych przestarzałych trybów szyfrowania np. CAST5 (podatny na [SWEET32](https://sweet32.info/)) oraz innych przestarzałych funkcji hashujących np. MD5 :

```
…/docs/atack-vectors master ? ❯ echo "Tajny tekst" | gpg --symmetric --cipher-algo CAST5 --digest-algo MD5 --allow-old-cipher-algos --batch --passphrase test1234  --output degraded_md5.gpg
```

W każdym z tych przypadków GnuPG w żaden sposób nie poinfiormowało, że używamy przestażałego algorytmu / funkcji hashującje podczas szyfrowania i bez zewnętrznej wiedzy o niebezpieczeństwie użytkownik nie wie, że nastawia się na potencjalny atak.

### Realizacja ataku dla age

age w używanej wersji zezwala na następujące opcje:

```
…/docs/atack-vectors master ? ❯ age --help
Usage:
    age [--encrypt] (-r RECIPIENT | -R PATH)... [--armor] [-o OUTPUT] [INPUT]
    age [--encrypt] --passphrase [--armor] [-o OUTPUT] [INPUT]
    age --decrypt [-i PATH]... [-o OUTPUT] [INPUT]

Options:
    -e, --encrypt               Encrypt the input to the output. Default if omitted.
    -d, --decrypt               Decrypt the input to the output.
    -o, --output OUTPUT         Write the result to the file at path OUTPUT.
    -a, --armor                 Encrypt to a PEM encoded format.
    -p, --passphrase            Encrypt with a passphrase.
    -r, --recipient RECIPIENT   Encrypt to the specified RECIPIENT. Can be repeated.
    -R, --recipients-file PATH  Encrypt to recipients listed at PATH. Can be repeated.
    -i, --identity PATH         Use the identity file at PATH. Can be repeated.
```

nie ma tam żadnej opcji modyfikowania algorytmów / funkcji hashijących.

## Wnioski

pgp w swojej dokumentacji w paragrafie 9 wylistowuje używane przez rozwiązanie algorytmów oraz kataloguje je do kategori MUST, SHOULD i MAY odnoczące się do implemetacji tych algorytmów w koljenych wersjach. Jak możemy tam przeczytać:

```
Implementations MUST implement TripleDES.  Implementations SHOULD implement AES-128 and CAST5.

Implementations MUST implement SHA-1.  Implementations MAY implement other algorithms.  MD5 is deprecated.
```
Wsparcia dla algorytmów takich jak 3DES czy SHA-1 nie można usunąć bez złamania kompatybilności z istniejącymi plikami i użytkownikami. A nawet gdy coś zostanie oznaczone jako deprecated (MD5) użytkownicy dalej mogą z tego korzystać.

W age nie ma możliwych do użcia algorytmów nie ma negocjacji, nie ma kompatybilności wstecznej ze słabymi szyfrowaniami w myśl zasady "Każdy punkt konfiguracji to potencjalny wektor ataku lub błąd użytkownika".

