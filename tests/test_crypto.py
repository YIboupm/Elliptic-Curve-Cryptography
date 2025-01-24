import os
from app.crypto import generate_ecc_key_pair, encrypt_file, decrypt_file

def test_key_generation():
    private_key, public_key = generate_ecc_key_pair()
    assert private_key is not None
    assert public_key is not None

def test_file_encryption_decryption(tmp_path):
    test_file = tmp_path / "test.txt"
    test_file.write_text("Hello, ECC Encryption!")
    private_key, public_key = generate_ecc_key_pair()
    
    encrypted_file = encrypt_file(str(test_file), public_key)
    decrypted_file = decrypt_file(encrypted_file, private_key)
    
    with open(decrypted_file, 'r') as f:
        assert f.read() == "Hello, ECC Encryption!"
