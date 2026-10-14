# SWEET32 Birthday Attack na 3DES

Atak urodzinowy na plaintext zakodowany za pomocą 3DES (64 bitowe bloki)

**Typ ataku:** Birthday Attack, collision attack 

**Źródło:** [On the Practical (In-)Security of 64-bit Block Ciphers](https://sweet32.info/SWEET32_CCS16.pdf)

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

3DES używa 64-bitowego bloku, gdy zaszyfrujemy w ten sposób 32GB danych tym samym kluczem/IV, prawdopodobieństwo zaistnienia paradoksu urodzinowego bloków cyphertextu przekracza 39%, co umożliwia odzysk informacji o plaintexcie bez znajomości klucza.

Pełna kolizja 64-bitowa wymaga 32–40 GB cyphertextu, jest to ciężkie do zademonstrowania w całości lokalnie. Zatem demonstracja składa się z dwóch uzupełniających się elementów:
- truncated birthday na realnych blokach 3DES ; ta sama matematyka stojąca za paradoksem urodzinowym ale proporcjonalnie mniejsza przestrzeń (kolizja w 4823 blokach = 38KB).
- wymuszona pełna kolizja CFB-64 (known-key) ; demonstruje właściwość XOR recovery


### Realizacja ataku dla pgp

Na początku należy odpowiednio zaszyfrować plik za pomocą pgp aby generował on cypher text zaszyfrowany za pomocą 3DES:


```
…/docs/atack-vectors master ? ❯ gpg --cipher-algo 3DES --allow-old-cipher-algos -c -o target.gpg secret.txt

…/docs/atack-vectors master ? ❯ gpg --list-packets target.gpg
gpg: dane zaszyfrowano za pomocą 3DES.CFB
gpg: zaszyfrowane jednym hasłem
# off=0 ctb=8c tag=3 hlen=2 plen=13
:symkey enc packet: version 4, cipher 2, aead 0, s2k 3, hash 10
        salt F58FB21EAA2F6A3A, count 65011712 (255)
# off=15 ctb=d2 tag=18 hlen=2 plen=112 new-ctb
:encrypted data packet:
        length: 112
        mdc_method: 2
# off=28 ctb=a3 tag=8 hlen=1 plen=0 indeterminate
:compressed packet: algo=1
# off=30 ctb=ac tag=11 hlen=2 plen=74
:literal data packet:
        mode b (62), created 1782045406, name="secret.txt",
        raw data: 58 bytes
```

Aby zaprezentować pierwszy element (tyruncated birthday na realnych blokach 3DES) 128KB danych zaszyfrowanych w 16384 blokach a następnie bloki były przeszukiwane pod względem kolizji na prefiksie. Udało się znaleść 7047 bloków gdzie taka kolizji nastąpiła:

```
i=3634: C[i] = 7d1b8f9897dc4720
j=7046: C[j] = 7d1b8f7cf6271b4b
C[i][:3] = C[j][:3]: 7d1b8f = 7d1b8f
```

Przejdźmy do prezentacji wymuszonej pełna kolizja CFB-64 wraz z XOR recovery. 
W trybie CFB-64 `C[i] = E_K(C[i-1]) XOR P[i]`, zatem gdy `C[i] = C[j]` to keystream dla następnych bloków jest identyczny (`E_K(C[i]) = E_K(C[j])`). Zatem możemy zapisać twierdzenie `C[i+1] XOR C[j+1] = P[i+1] XOR P[j+1]`. Ta zależność jest obserwowalna wyłącznie z cyphertextem do którego nie znamy klucza. Takie wymuszenie możemy zaobserowować zanając szyfrowany fragment wiadomości:

```
C[2] = e6356f1e7d22362b  (kotwica kolizji — blok odniesienia)
  C[5] = e6356f1e7d22362b  (wymuszona kolizja z C[2])
  C[2] == C[5]: True

  P[3] XOR P[6] = 140017726a746975  (nieznane atakującemu — P[6] jest sekretem)
  C[3] XOR C[6] = 140017726a746975  (obserwowalne z samego szyfrogramu)
  Równość:       True

  [!!] Gdy C[i]=C[j], to P[i+1] XOR P[j+1] = C[i+1] XOR C[j+1] (bez klucza)
  [!!] Znając P[3] (blok znany), atakujący odzyskuje P[6] (blok tajny):

     P[3] znany:   b'GET / HT'
     P[6] sekret:  b'SECRET!!'
     P[6] odzysk:  b'SECRET!!'
     Odzysk poprawny: True
```

Wymuszona kolizja (known-key PoC, metodologia Sec. 5 pracy SWEET32):

### Realizacja ataku dla age

age nie obsługuje szyfrowania plików za pomocą 3DES używa szyfrowania strumieniowego (ChaCha20) wiec nie ma bloków na kßórych można by przeprowadzić atak z wykorzystaneim paradoksu urodzinowego. Próg urodzinowy dla age dotyczy przestrzeni nonce (2^96) i aby był on skuteczny wymagałby 2^48 wiadomości zaszyfrowanych tym samym kluczem co w praktyce jest nieosiągalne.

## Wnioski

RFC 4880 czyni 3DES obowiązkowowym do implementacji każdy klient OpenPGP musi go implementować, co gwarantuje dostępność podatnego szyfru w każdej konfiguracji. 64-bitowy blok 3DES podlega atakowi z wykorzystaniem paradoksu urodzinowego: P(kolizji) = 39.3% po 32 GB, 50% po <40 GB, osiągalne w mniej niż godzinę na typowym CPU. age jest strukturalnie odporne z racji używania szyfru strumieniowego co eliminuje klasę ataków urodzinowych na bloki.
