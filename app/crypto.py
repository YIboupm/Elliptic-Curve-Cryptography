from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import struct

def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def encrypt_file(file_path, public_key):
    private_key = ec.generate_private_key(ec.SECP256R1())
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    # 生成 AES 密钥
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption',
    ).derive(shared_key)

    iv = os.urandom(16)

    # AES 加密文件内容
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # 序列化 PEM 格式的公钥
    pem_public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # 获取 PEM 公钥的长度并转换为 4 字节
    pem_len = struct.pack("I", len(pem_public_key))  # 4 字节存储公钥长度

    # 组合数据：公钥长度 + 公钥 + IV + 密文
    encrypted_file_path = file_path + ".enc"
    with open(encrypted_file_path, 'wb') as f:
        f.write(pem_len + pem_public_key + iv + ciphertext)

    return encrypted_file_path

def decrypt_file(encrypted_file_path, private_key):
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()

    # 提取公钥长度（前 4 字节）
    pem_len = struct.unpack("I", encrypted_data[:4])[0]

    # 提取 PEM 公钥
    pem_public_key = encrypted_data[4:4 + pem_len]
    iv = encrypted_data[4 + pem_len:4 + pem_len + 16]
    ciphertext = encrypted_data[4 + pem_len + 16:]

    # 解析 ECC 公钥
    try:
        public_key = serialization.load_pem_public_key(pem_public_key)
    except ValueError as e:
        raise ValueError("ECC 公钥格式错误，解密失败") from e

    # 计算共享密钥
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    # 生成 AES 密钥
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption',
    ).derive(shared_key)

    # 解密数据
    cipher = Cipher(algorithms.AES(derived_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    decrypted_file_path = encrypted_file_path.replace(".enc", ".mp3")
    with open(decrypted_file_path, 'wb') as f:
        f.write(plaintext)

    return decrypted_file_path




