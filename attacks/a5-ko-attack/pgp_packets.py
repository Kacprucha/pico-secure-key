import hashlib, struct, time

def mpi(n: int) -> bytes:
    if n == 0:
        return b"\x00\x00"
    
    nbytes = (n.bit_length() + 7) // 8
    
    return struct.pack(">H", n.bit_length()) + n.to_bytes(nbytes, "big")

def new_format_length(L: int) -> bytes:
    if L < 192: 
        return bytes([L])
    elif L < 8384:
        L2 = L - 192
        return bytes([192 + (L2 >> 8), L2 & 0xFF])
    else:
        return bytes([0xFF]) + struct.pack(">I", L)

def packet(tag: int, body: bytes) -> bytes:
    return bytes([0xC0 | tag]) + new_format_length(len(body)) + body

def dsa_secret_key_body(created: int, p: int, q: int, g: int, y: int, s2k_bytes: bytes, encrypted_blob: bytes) -> bytes:
    return (bytes([0x04]) + struct.pack(">I", created) + bytes([17]) + mpi(p) + mpi(q) + mpi(g) + mpi(y) + s2k_bytes + encrypted_blob)

def userid_body(uid_text: str) -> bytes:
    return uid_text.encode("utf-8")

def sig_hashed_subpackets(creation_time: int, issuer_fpr: bytes, key_flags: int = 0x03) -> bytes:
    sp = b""
    sp += bytes([5, 2]) + struct.pack(">I", creation_time) 
    sp += bytes([22, 33, 4]) + issuer_fpr 
    sp += bytes([2, 27, key_flags])   
    return sp

def build_cert_signature_hash_input(pubkey_body: bytes, uid_text: str, sig_version: int, sig_type: int, pubalgo: int, hashalgo: int, hashed_subpkts: bytes) -> bytes:
    pk_part = b"\x99" + struct.pack(">H", len(pubkey_body)) + pubkey_body
    uid_bytes = uid_text.encode("utf-8")
    uid_part = b"\xb4" + struct.pack(">I", len(uid_bytes)) + uid_bytes
    sig_hashed_part = (bytes([sig_version, sig_type, pubalgo, hashalgo]) + struct.pack(">H", len(hashed_subpkts)) + hashed_subpkts)
    trailer = bytes([0x04, 0xFF]) + struct.pack(">I", len(sig_hashed_part))
    
    return pk_part + uid_part + sig_hashed_part + trailer

def dsa_truncate_hash(digest: bytes, q_bitlen: int) -> int:
    n_bytes = (q_bitlen + 7) // 8
    truncated = digest[:n_bytes]
    val = int.from_bytes(truncated, "big")
    extra_bits = n_bytes * 8 - q_bitlen
    
    if extra_bits:
        val >>= extra_bits
    
    return val

def build_signature_packet(sig_type: int, pubalgo: int, hashalgo: int, hashed_subpkts: bytes, issuer_keyid: bytes, r: int, s: int, digest_prefix: bytes) -> bytes:
    unhashed_subpkts = bytes([9, 16]) + issuer_keyid  
    body = (bytes([4, sig_type, pubalgo, hashalgo])
            + struct.pack(">H", len(hashed_subpkts)) + hashed_subpkts
            + struct.pack(">H", len(unhashed_subpkts)) + unhashed_subpkts
            + digest_prefix[:2]
            + mpi(r) + mpi(s))
    
    return body

def build_doc_signature_hash_input(message: bytes, sig_version: int, sig_type: int, pubalgo: int, hashalgo: int, hashed_subpkts: bytes) -> bytes:
    sig_hashed_part = (bytes([sig_version, sig_type, pubalgo, hashalgo]) + struct.pack(">H", len(hashed_subpkts)) + hashed_subpkts)
    trailer = bytes([0x04, 0xFF]) + struct.pack(">I", len(sig_hashed_part))
    
    return message + sig_hashed_part + trailer

def sig_hashed_subpackets_doc(creation_time: int) -> bytes:
    return bytes([5, 2]) + struct.pack(">I", creation_time)

HASH_ALGOS = {2: hashlib.sha1, 8: hashlib.sha256, 10: hashlib.sha512}