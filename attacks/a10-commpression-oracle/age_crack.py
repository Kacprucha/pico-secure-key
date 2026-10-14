import subprocess

AGE_PUB_KEY = "age18ujjc3ahxhc29wuerz8p9yu8039txpurls6pkdsgvg99ahzrsdyq462a6d"
CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789"

# symulacja działania serwera

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

# atak oracle

size = age_encrypt_size("")
base_line_size = size
print(f"Rozmiar ciphertextu bez wstrzyknięcia: {base_line_size}B")

guessed = ""
for position in range(4):
    sizes = [age_encrypt_size(f"eyJhbGciOiJIUzI1NiJ9.{guessed}{c}") for c in CHARS]
    delta = max(sizes) - min(sizes)
    print(f"\tPozycja {position+1}: min={min(sizes)}B max={max(sizes)}B delta={delta}B")