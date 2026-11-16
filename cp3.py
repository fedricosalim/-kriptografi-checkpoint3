"""
Checkpoint 3: mekanisme kunci password manager (zero-knowledge vault)
pip install argon2-cffi cryptography
"""
import os, json, hmac, hashlib
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


def derive_keys(master_password: str, salt: bytes):
    """Master password -> Argon2id -> dua kunci terpisah (HKDF)."""
    master = hash_secret_raw(master_password.encode(), salt,
                             time_cost=3, memory_cost=65536,
                             parallelism=4, hash_len=32, type=Type.ID)
    k_enc = HKDF(hashes.SHA256(), 32, None, b"vault-encryption").derive(master)
    k_auth = HKDF(hashes.SHA256(), 32, None, b"server-login").derive(master)
    return k_enc, k_auth


def seal_vault(k_enc: bytes, vault: dict, user_id: str, version: int) -> dict:
    """Enkripsi vault dengan AES-256-GCM; user_id dan version diikat sebagai AAD."""
    nonce = os.urandom(12)
    aad = f"{user_id}|{version}".encode()
    ct = AESGCM(k_enc).encrypt(nonce, json.dumps(vault).encode(), aad)
    return {"version": version, "nonce": nonce, "ct": ct}


def open_vault(k_enc: bytes, blob: dict, user_id: str, min_version: int) -> dict:
    """Dekripsi di sisi klien; tolak versi lama (rollback) dan data yang diubah."""
    if blob["version"] < min_version:
        raise ValueError("ROLLBACK: versi vault lebih lama dari yang pernah dilihat klien")
    aad = f"{user_id}|{blob['version']}".encode()
    return json.loads(AESGCM(k_enc).decrypt(blob["nonce"], blob["ct"], aad))


def server_store(k_auth: bytes) -> bytes:
    """Server hanya menyimpan hash dari k_auth, bukan k_auth dan bukan k_enc."""
    return hashlib.sha256(k_auth).digest()


def server_verify(stored: bytes, k_auth_dikirim: bytes) -> bool:
    return hmac.compare_digest(stored, hashlib.sha256(k_auth_dikirim).digest())


if __name__ == "__main__":
    salt = os.urandom(16)
    k_enc, k_auth = derive_keys("Kopi!Pagi#2026", salt)
    stored = server_store(k_auth)

    vault = {"github.com": "p@ss-1", "bank.co.id": "p@ss-2"}
    blob = seal_vault(k_enc, vault, "andi", version=5)

    print("1. Dekripsi normal        :", open_vault(k_enc, blob, "andi", 5))

    rusak = dict(blob); rusak["ct"] = bytes([blob["ct"][0] ^ 1]) + blob["ct"][1:]
    try: open_vault(k_enc, rusak, "andi", 5)
    except InvalidTag: print("2. Ciphertext diubah 1 bit: DITOLAK (InvalidTag)")

    lama = seal_vault(k_enc, vault, "andi", version=3)
    try: open_vault(k_enc, lama, "andi", 5)
    except ValueError as e: print("3. Versi lama dikirim ulang:", e)

    swap = dict(blob); swap["version"] = 6
    try: open_vault(k_enc, swap, "andi", 5)
    except InvalidTag: print("4. Nomor versi dipalsukan  : DITOLAK (AAD tidak cocok)")

    k_enc2, k_auth2 = derive_keys("password-tebakan", salt)
    print("5. Login password benar   :", server_verify(stored, k_auth))
    print("6. Login password salah   :", server_verify(stored, k_auth2))
    print("7. k_enc != k_auth        :", k_enc != k_auth)