from fastapi import APIRouter
from app.crypto import generate_ecc_key_pair, encrypt_file, decrypt_file,serialize_private_key, serialize_public_key

router = APIRouter()

@router.get("/generate-keys")
def generate_keys():
    private_key, public_key = generate_ecc_key_pair()
    return {
        "private_key": serialize_private_key(private_key),
        "public_key": serialize_public_key(public_key)
    }

@router.post("/encrypt")
def encrypt(filename: str):
    _, public_key = generate_ecc_key_pair()
    encrypted_file = encrypt_file(filename, public_key)
    return {"encrypted_file": encrypted_file}

@router.post("/decrypt")
def decrypt(filename: str):
    private_key, _ = generate_ecc_key_pair()
    decrypted_file = decrypt_file(filename, private_key)
    return {"decrypted_file": decrypted_file}