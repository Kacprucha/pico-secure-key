# Adaptive Chosen-Ciphertext Attack

Modyfikacja bajtu ciphertextu daje kontrolowaną zmianę plaintextu bez znajomości klucza

**Typ ataku:** Adaptive Chosen-Ciphertext Attack (CCA2), partial plaintext recovery

**Źródło:** [Implementation of Chosen-Ciphertext Attacks against PGP and GnuPG](https://www.schneier.com/academic/archives/2002/01/implementation_of_ch.html), [An Attack on CFB Mode Encryption As Used By OpenPGP](https://eprint.iacr.org/2005/033.pdf)

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

Atakujący przechwytując zaszyfrowany plik z trybem CFB. Następnie poprzez modyfikację plaintextu za pomocą operacji XOR może on otrzymać modyfikację plaintextu która będzie przechodzić quick-check podczas próby deszyfrowania. Atakujący wiec przystępuje do odszyfrowywania tak zmienionego cypher text wiedząc, że operacja XOR została nanesiona na odszyfrowany tekst:

```
plaintext[16+i]  =  ct[34+i]  XOR  E(ct[18:34])[i]
                    ↑              ↑
                 znany             NIEZNANY
                 atakującemu      (wymaga klucza)

plaintext'[16+i]  =  (ct[34+i] XOR 0x20)  XOR  E(ct[18:34])[i]  =   ct[34+i]  XOR  E(ct[18:34])[i]  XOR 0x20  =   plaintext[16+i]  XOR  0x20
```

Znając tą zależność można zacząc zgadywać co jest faktycznie w zaszyfrowanym pliku. Jeżeli atakujący wybierze modyfikację o 0x20 to zamienia na poczatku `ct[34] ^= 0x20` i odpytuje jakąś formę wyroczni (np serwis mailowy) co zostanie zwrócone. Oracle zwraca: `wyjście'[8] = 0x6B ('k')` dzięki temu atakujący może obliczyć: `wyjście[8] = wyjście'[8] XOR delta = 0x6B XOR 0x20 = 0x4B = 'K'`.

### Realizacja ataku dla pgp

Rozpoczynamy od zaszyfrowania tajnej wiadomości z odpowiednimi flagami:

```
…/docs/atack-vectors master ? ❯ echo "TAJNY DOKUMENT: klucz dostepu XK-7734-ALFA" | \
gpg --symmetric --cipher-algo AES128 --compress-algo none --s2k-digest-algo SHA1 --allow-old-cipher-algos --batch --passphrase "demo" --output target.gpg
```

Następnie znając strukturę szyfrowania pliku pgp z trybem CFB:
```
ct[0:16]  = E_key(IV=0x00×16) XOR prefix_losowy → PREFIX
ct[16:18] = E_key(ct[0:16]) XOR prefix[14:16] → QUICK CHECK
ct[18:34] = E_key(ct[2:18]) XOR plaintext[0:16] → BLOK 0 plaintextu
ct[34:50] = E_key(ct[18:34]) XOR plaintext[16:32] → BLOK 1 plaintextu
ct[50:66] = E_key(ct[34:50]) XOR plaintext[32:48] → BLOK 2 plaintextu
```

Wiedząc jakie fragmenty cyphertextu odpowiadają za jakie elemty wiemy że musimy modyfikować bajty od 34 w górę aby nie wpłynąć na modyfikację elementów cyphertextu, które odpowiadają za qucik check. Wiedząc to możemy za pomoca skryptu (z symulowaną oracle) zgadaywać co znajduje się wenwnątrz zaszyfrowanego pliku:

```
…/atack-vectors/a2-adaptive-chosen-ciphertext master  ? ✗ python3 mz_cca.py
======================================================================
ATAK MISTER-ZUCCHERATO - wyrocznia 1-bitowa
======================================================================
C1=1f5d24f85cc275c413e6774ab3e7a833  C2=6368  C3=c8e2421985c5f2f2600cddd1a4708e7c  C4=db269d0d7d22aaef9584b2054bdccffb

[Faza A] Wyznaczanie [E_K(0)]_(b-1,b) -- setup, oczekiwane ~2^15 zapytań
    Znane 2 bajty M1 (przewidziane ze struktury pakietu): b'\xcb0'
    ... 4096/65536 zapytań (15 zapytań/s, upłynęło 267s)
    ... 8192/65536 zapytań (15 zapytań/s, upłynęło 532s)
    ... 12288/65536 zapytań (15 zapytań/s, upłynęło 796s)
    ... 16384/65536 zapytań (15 zapytań/s, upłynęło 1061s)
    ... 20480/65536 zapytań (15 zapytań/s, upłynęło 1326s)
    ... 24576/65536 zapytań (15 zapytań/s, upłynęło 1591s)
    ... 28672/65536 zapytań (15 zapytań/s, upłynęło 1856s)
    ... 32768/65536 zapytań (15 zapytań/s, upłynęło 2121s)
    ... 36864/65536 zapytań (15 zapytań/s, upłynęło 2386s)
    ... 40960/65536 zapytań (15 zapytań/s, upłynęło 2652s)
    ... 45056/65536 zapytań (15 zapytań/s, upłynęło 2919s)
    ... 49152/65536 zapytań (15 zapytań/s, upłynęło 3185s)
    ... 53248/65536 zapytań (15 zapytań/s, upłynęło 3452s)
    ... 57344/65536 zapytań (15 zapytań/s, upłynęło 3718s)
    [+] Znaleziono D=0xe183 po 57732 zapytaniach (3743.1s)
    [E_K(0)]_(b-1,b) = 8139

[Faza B] Odzyskiwanie [M2]_1,2 -- atak właściwy, oczekiwane ~2^15 zapytań
    ... 4096/65536 zapytań (15 zapytań/s, upłynęło 266s)
    ... 8192/65536 zapytań (15 zapytań/s, upłynęło 532s)
    ... 12288/65536 zapytań (15 zapytań/s, upłynęło 797s)
    ... 16384/65536 zapytań (15 zapytań/s, upłynęło 1062s)
    ... 20480/65536 zapytań (15 zapytań/s, upłynęło 1327s)
    ... 24576/65536 zapytań (15 zapytań/s, upłynęło 1595s)
    ... 28672/65536 zapytań (15 zapytań/s, upłynęło 1861s)
    ... 32768/65536 zapytań (15 zapytań/s, upłynęło 2127s)
    ... 36864/65536 zapytań (15 zapytań/s, upłynęło 2393s)
    [+] Znaleziono D=0x9f36 po 40759 zapytaniach (2644.9s)
    [E_K(C3)]_1,2 = 9073
    Odzyskane [M2]_1,2 = b'KU' (hex: 4b55)

======================================================================
Prawdziwe [M2]_1,2  : b'KU'
Odzyskane [M2]_1,2  : b'KU'
Zgodność            : OK
Łączna liczba zapytań do wyroczni: 98493 (teoria: ~2 x 2^15 = ~65536 średnio)
======================================================================
```

### Realizacja ataku dla age

Tak jak w przypadku pgp szyfrujemy tajną wiadomość:

```
…/docs/atack-vectors master ? ❯ age-keygen -o age.key
Public key: age1l4juzmxes92t65jd905vu7nnkcm28jxx8g7nq4ecef04jee7ag3ssuap30

…/docs/atack-vectors master ? ❯ age -r $(age-keygen -y age.key) -o target.age secret.txt
```

Tu ponownie modyfikujemy bity w cyphertexcie i próbójemy odszyfrować tak zmieniony plik. age zwraca kod błedu 1, odmowy odszyfrowania, z komunikatem `age: error: no identity matched any of the recipients`. Na wyjściu nie jest nic zwracane.

## Wnioski

gpg ma dwa mechanizmy obrony przed modyfikacją cyphertextu quick check i MDC. Quick check nie wykrywa wprowadzanych manipulacji bo modyfikujemy `ct[34+]`, a nie `ct[16:18]`. MDC wykrywa te modyfikacje ale tylko jeśli klient sprawdza i reaguje na zwracany błąd. W 2018 roku większość klientów emailowych ignorowała ten kod wyjścia. 
Jest to wada architektury gpg, która rozdziela autentykację od mechanizmu szybkiej weryfikacji.

age używa ChaCha20-Poly1305 (AEAD), który jest z definicji IND-CCA2 bezpieczny. Każda modyfikacja ciphertextu powoduje weryfikację tagu Poly1305, która zawsze kończy się odmową zwrócenia plaintextu.


