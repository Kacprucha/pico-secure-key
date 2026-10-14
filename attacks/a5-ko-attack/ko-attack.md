# KO Attack (Key Overwriting)

Secret Key Packet w OpenPGP nie wiąże kryptograficznie pól publicznych z zaszyfrowanymi parametrami prywatnymi

**Typ ataku:** Logic Error

**Źródło:** [„Victory by KO: Attacking OpenPGP Using Key Overwriting∗"](https://www.kopenpgp.com/assets/paper.pdf)

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

Atakujący z dostępem do pliku zaszyfrowanego klucza (backup, USB, transfer) może nadpisać metadane publiczne i wykorzystując fakt, że algorytmy rodziny DSA np. EdDSA, ECDSA ,ECDH mają wszystkie jeden parametr sekretny, poprzez przekonwertowanie klucz na DSA, po czym odzyskać cały sekret z analizy "faulty signature" wyprodukowanej przez ofiarę.

Atak dotyczy klucza w przenośnym formacie OpenPGP nie klucza już zaimportowanego do keyringu GnuPG. Od wersji 2.2.23 GnuPG (rok wydania wersji 2020) chroni klucze w keyringu własnym, niestandardowym extended key format agenta, który nie podlega tej klasie ataków. Atak jest więc realny w scenariuszu gdy ofiara przechowuje zaszyfrowany plik `.gpg` w miejscu dostępnym atakującemu, a atakujący modyfikuje go przed importem przez ofiarę gdy ofiara korzysta ze niższej wersji GnuPG niż 2.2.23 (jest to realna sytuacji z racji na podtrzymywanie w użyciu wersji 1.4).

### Realizacja ataku dla pgp

Do przeprowadzenia ataku potrzebujemy zbudować klucz EdDSA chroniony hasłem:

```
cat > keygen.batch << 'EOF'
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: sign
Name-Real: Victim
Name-Email: victim@test.com
Expire-Date: 0
Passphrase: zaq1@WSX
%commit
EOF

gpg --batch --pinentry-mode loopback --gen-key keygen.batch
```

oraz wyeksportować klucz prywatny do pliku:

```
gpg --export-secret-keys -o victim.gpg "victim@test.com"
```

Z analizy struktury wygenerowanego pliku z kluczem prywatnym oraz dokmentacji pgp możemy stweirdzić że segment zawierający dane publiczne (wersja, date utworzenia, użyty algorytm, OID krzywej, publiczny punkt Q) jest zapisany w plaintext, a sam klucz jest zapisany w zaszyfrowanym blobie poprzez MPI oraz sume kontrolną utworzoną przy pomocy SHA-1. SHA-1 w zaszyfrowanym blobie chroni integralność sekretu wobec samego siebie nie wobec pól publicznych. Nic w formacie nie wiąże deklarowanego algorytmu z zawartością zaszyfrowanego blobu.

Próba wykorzystania ataków brutalnej siły by wokorzystać tą niedokładność nie powiodła się niestety z racji, że aktualnie GnuPG odrzuca podpisy DSA z q mniejszym niż 160 bit jako "unsafe hash", niezależnie od poprawności matematycznej. Konsekwencją tego jest, że tani brute-force (q - 16 bit, 18 rund dla 256-bit sekretu) jest blokowany na najnowszym GnuPG. Wymagane q większe od 160 bit czyni odzysk reszty `x mod q` obliczeniowo niewykonalne na lokalnym sprzęcie. 

Wobec opisanej wyżej pełną ekstrakcję zademonstrowano wobec symulowanej biblioteki bez walidacji `y=g^x mod p`. Sekret jest odszyfrowywany prawdziwą biblioteką kryptograficzną (pgpy + cryptography), a symulowana jest tylko logika biblioteki podpisującej bez walidacji. Atakujący w tej symulacji jest w pełni ślepy nie zna `x_real`, używa `y'=1` niewymagający żadnej wiedzy o sekrecie.

Wyniki z przeprowadzonej symulacji:

```
Pelna ekstrakcja sekretu (symulacja biblioteka bez walidacji DSA)

  [!]  Symulacja modeluje Sequoia / stary OpenPGP.js<4.10.5 / stary gopenpgp<2.1
Parametry: 18 rund (jak Tabela 1 pracy: '256-bit x: 18'),
q_bits=16 per runda, 2 sygnatury/runda

  runda  1/18: q= 63863 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda  2/18: q= 38453 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda  3/18: q= 49223 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda  4/18: q= 43283 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda  5/18: q= 49363 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda  6/18: q= 64663 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda  7/18: q= 58543 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda  8/18: q= 46051 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda  9/18: q= 42157 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda 10/18: q= 58549 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda 11/18: q= 41887 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda 12/18: q= 59441 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda 13/18: q= 37799 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda 14/18: q= 59023 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda 15/18: q= 45179 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda 16/18: q= 41957 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda 17/18: q= 64381 (16b)  kandydatow=1  zgodnosc_czesciowa=True
  runda 18/18: q= 45821 (16b)  kandydatow=1  zgodnosc_czesciowa=True

Rund uzytych: 18/18 (niejednoznacznych: 0)
Czas calkowity: 72.0s (4.00s/runda)
CRT-modulus (iloczyn q_i): 281 bit (sekret: 254 bit)

  [!!] Pelne odzyskanie sekretu: x_recovered == x_real (256/256 bit)
  [!!] x_recovered = 26492316352622927398216589442936456357062431157068375494939031984691166590484
```

### Realizacja ataku dla age

Format age nie przechowuje osobnych pól publicznych przy sekrecie zatem brak pola algorytmu, brak parametrów grupy, brak OID krzywej. Cały klucz to nieinterpretowalny ciąg 32 bajtów X25519. Klasa ataku KO jest w age strukturalnie niewyrażalna, gdyż nie istnieje inny algorytm do podstawienia, bo age obsługuje wyłącznie X25519.

## Wnioski

OpenPGP Secret Key Packet nie wiąże kryptograficznie pól publicznych z prywatnymi przez co Cross-algorithm substitution (EdDSA ns DSA) jest akceptowana przez GnuPG 2.4.4 na poziomie importu. Strukturalna podatność dalej istnieje mimo dalszych aktualizacji protokołu. Jednakże GnuPG 2.4.4 z libgcrypt 1.10.3 wprowadził pewne zmiany uniemożliwiając przeprowadzenie skutecznego prostego ataku KO. Jeżeli jednak zostaną użyte biblioteki bez walidacji (Sequoia, stary OpenPGP.js < 4.10.5, stary gopenpgp < 2.1, stary RNP < 0.16), atak odzyskuje cały sekret z realnych bajtów klucza ofiary. age jest odporny strukturalnie z racji na brak pól metadanych do nadpisania eliminując w ten sposób całą klasę ataku, niezależnie od implementacji.