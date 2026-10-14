# Offline Brute-Force

Modyfikacja bajtu ciphertextu daje kontrolowaną zmianę plaintextu bez znajomości klucza

**Typ ataku:** Offline Dictionary/Brute-Force Attack

**Źródło:** [SoK: Why Johnny Can’t Fix PGP Standardization](https://arxiv.org/pdf/2008.06913)

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

Karta graficzna
```
NVIDIA GeForce RTX 5070
```


## Scenariusz ataku

Tajny dokument zaszyfrowany za pomocą passphrase używającego SHA-1 jako funkcji hasującej jest podanty na krytyczną wadę funkcji hashującej jaką jest brak przygotowania na ataki z użyciem dużej mocy obliczeniowej idącą za użyciem GPU do przeprowadzenia ataków tupy brut-force lub dictionary attack. Atakujący przechwytuje zaszyfrowany plik następnie odczytuje parametry S2K z nagłówka, interesuje go rodzaj użytej funkcjim sól oraz licznik iteracji. Następnie na podsatwie zebranych infromacji przeprowadza atak polegający na hashowaniu haseł i  porównywania ich z hashem uzyskanym z zaszyfrowanego pliku. Dzięki słabości SHA-1, funkcja była zaprojektowana z myślą o szybkości nie do KDF, GPU może obliczyć wiele hasów na sekundę powodując ataki brutalnej siły jako skuteczne.

### Realizacja ataku dla pgp

W najnowszych implementacjach gpg wymieniło SHA-1 jako podstawową funkcję hashującą na Argon2 ale dalej da się wymusić aby gpg zaszyfrowało plik z wykorzystaniem przestażałych funkcji hashujących:

```
…/docs/atack-vectors master ? ❯ gpg --symmetric --cipher-algo AES256 --compress-algo none --s2k-digest-algo SHA1 --allow-old-cipher-algos --batch --passphrase "111111" --output target_medium.gpg secret.txt

```

Z nagłówka pgp możemy odczytać interesujące nas informacje takie jak rodzaj funkcji, sól czy ilość prób:

```
:symkey enc packet: version 4, cipher 9, aead 0, s2k 3, hash 2
        salt 4E2E2A74EDF9B69B, count 65011712 (255)
```

Możemy użyć programu hashcat do pomiaru czasu jaki zajmie GPU do "złamania" SHA-1. Wykorzystamy tutaj tryb pracy `--benchmark` w tedy hashcat nie bierze żadnego pliku z hashami ani wordlisty, generuje wewnętrznie losowe dane i mierzy ile operacji KDF potrafi wykonać na sekundę na GPU maszyny. hashcat ma już zaimplementowany tryb do łamania haseł plików pgp zaszyfrowanych za pomocą hasła: GPG (AES-128/AES-256 (SHA-1($pass))) o id 17010. 

```
…/docs/atack-vectors master ? ✗ hashcat --benchmark -m 17010
hashcat (v7.1.2) starting in benchmark mode

Benchmarking uses hand-optimized kernel code by default.
You can use it in your cracking session by setting the -O option.
Note: Using optimized kernel code limits the maximum supported password length.
To disable the optimized kernel code in benchmark mode, use the -w option.

Kernel /usr/share/hashcat/OpenCL/m17010-optimized.cl:
Optimized kernel requested, but not available or not required
Falling back to pure kernel

Successfully initialized the NVIDIA main driver CUDA runtime library.

Failed to initialize NVIDIA RTC library.

* Device #1: CUDA SDK Toolkit not installed or incorrectly installed.
             CUDA SDK Toolkit required for proper device support and utilization.
             For more information, see: https://hashcat.net/faq/wrongdriver
             Falling back to OpenCL runtime.

OpenCL API (OpenCL 3.0 CUDA 13.2.82) - Platform #1 [NVIDIA Corporation]
=======================================================================
* Device #01: NVIDIA GeForce RTX 5070, 11765/11765 MB (2941 MB allocatable), 48MCU

Benchmark relevant options:
===========================
* --backend-devices-virtmulti=1
* --backend-devices-virthost=1
* --optimized-kernel-enable

----------------------------------------------------------------------------
* Hash-Mode 17010 (GPG (AES-128/AES-256 (SHA-1($pass)))) [Iterations: 65536]
----------------------------------------------------------------------------

Speed.#01........: 13186.3 kH/s (83.37ms) @ Accel:96 Loops:65536 Thr:256 Vec:1

Started: Sun Jun  7 03:03:19 2026
Stopped: Sun Jun  7 03:03:26 2026
```

Benchmark wykazał że hashcat może wykonać 13186300 operacji kryptograficznych na sekdundę, zatem czas na jedną próbę wynosi w przybliżeniu 75,83 ns.

### Realizacja ataku dla age

Podobnnie jak dla pgp na początku przygotowujemy zaszyfrowany plik za pomocą passphrase. 

```
…/docs/atack-vectors master ? ✗ age --passphrase -o target_age.age  secret.txt
```

W trakcie procesu szyfrowania zostało podane to samo hasło co dla pliku pgp: 111111.
Ponownie z hedera zaszyfrowanego pliku możemy odczytać algorytm oraz sól hasła:

```
-> scrypt 7h40dxTrhWX8YLYasjyggw 18
```

age natywnie używa funkcji scrypt do przeprowadzenia operacji KDF.
Ponownie możemy posłużyć się hashcat aby zobaczyć ile zajeło by programowi do złamania hasła do pliku age, gdyż posiada on tryb dla funkcji scrypt o id 8900.

```
…/docs/atack-vectors master ? ❯ hashcat --benchmark -m 8900
hashcat (v7.1.2) starting in benchmark mode

Benchmarking uses hand-optimized kernel code by default.
You can use it in your cracking session by setting the -O option.
Note: Using optimized kernel code limits the maximum supported password length.
To disable the optimized kernel code in benchmark mode, use the -w option.

Kernel /usr/share/hashcat/OpenCL/m08900-optimized.cl:
Optimized kernel requested, but not available or not required
Falling back to pure kernel

Successfully initialized the NVIDIA main driver CUDA runtime library.

Failed to initialize NVIDIA RTC library.

* Device #1: CUDA SDK Toolkit not installed or incorrectly installed.
             CUDA SDK Toolkit required for proper device support and utilization.
             For more information, see: https://hashcat.net/faq/wrongdriver
             Falling back to OpenCL runtime.

OpenCL API (OpenCL 3.0 CUDA 13.2.82) - Platform #1 [NVIDIA Corporation]
=======================================================================
* Device #01: NVIDIA GeForce RTX 5070, 11765/11765 MB (2941 MB allocatable), 48MCU

Benchmark relevant options:
===========================
* --backend-devices-virtmulti=1
* --backend-devices-virthost=1
* --optimized-kernel-enable

---------------------------------------------
* Hash-Mode 8900 (scrypt) [Iterations: 16384]
---------------------------------------------

Speed.#01........:     3703 H/s (70.16ms) @ Accel:78 Loops:2048 Thr:32 Vec:1

Started: Sun Jun  7 03:03:36 2026
Stopped: Sun Jun  7 03:03:41 2026
```
Benchmark wykazał że hashcat może wykonać 3703 operacji kryptograficznych na sekdundę, zatem czas na jedną próbę wynosi w przybliżeniu 0,27 ms.

## Wnioski

Z wylicznych benchamrków można zobaczyć, że pgp jest 3560.978 razy szybszy od age. Daje to realną różnicę dla przeszukiwania dużych banków haseł np rockyou.txt zawierającym 14 milionów haseł. Zakładając najgorszy senariusz, że program będzie musiał przejrzeć wszystkie hasła to dla pgp proces zajmie 1,06s a dla age zajmie to 1,05h.

Podatnością tutaj nie jest stwierdzenie, że pgp jest mniej podatne na brutforce niż age każde hasło można złamać w skończonej ilości czasu, ale właśnie ten czas tutaj jest kluczowy dla SHA-1 z wykorzystaniem nowoczesnych kart graficznych przeszukanie milionów haseł zajmuje skeudny co umożliwia realne przeprowadzanie ataków brutalnej siły. age używając skrypt zapobiega się przed tym znacznie wydłużając czas powodując, że taki atak zajoł by zbyt długo dla atakującego aby mógł realnie z niego skorzystać. Dzieje się to dlatego, że scrypt jest memory-hard czyli GPU nie mogą efektywnie przeprowadzić ataku ze względu na wymóg dużej pamięci RAM.


