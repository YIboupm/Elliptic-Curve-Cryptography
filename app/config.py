from fastapi import FastAPI
from app.crypto import generate_ecc_key_pair, encrypt_file, decrypt_file, serialize_private_key, serialize_public_key

# 在应用启动时生成密钥
private_key, public_key = generate_ecc_key_pair()

app = FastAPI()

@app.get("/generate-keys")
def generate_keys():
    return {
        "private_key": serialize_private_key(private_key),
        "public_key": serialize_public_key(public_key)
    }

@app.post("/encrypt")
def encrypt(filename: str):
    encrypted_file = encrypt_file(filename, public_key)
    return {"encrypted_file": encrypted_file}

@app.post("/decrypt")
def decrypt(filename: str):
    decrypted_file = decrypt_file(filename, private_key)
    return {"decrypted_file": decrypted_file}

