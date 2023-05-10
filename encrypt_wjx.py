import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def generate_aes_key():
    password = b'password' # 可以自定义密码
    salt = b'salt' # 可以自定义盐值
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

def aes_encrypt(key, iv, data):
    # 使用PKCS7填充方式对数据进行填充
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # 创建AES-CBC加密器
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).encryptor()

    # 对填充后的数据进行加密
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data


def aes_decrypt(key, iv, encrypted_data):
    # 创建AES-CBC解密器
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()

    # 对加密后的数据进行解密
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # 使用PKCS7填充方式对解密后的数据进行去除填充
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(decrypted_data) + unpadder.finalize()

    return data

# 获取命令行参数
if len(sys.argv) < 2:
    print("Usage: python script.py [file]")
    sys.exit(1)

file_path = sys.argv[1]

# 读取文件内容
with open(file_path, 'rb') as f:
    data = f.read()

# 生成随机密码和IV
password = os.urandom(16)
salt = os.urandom(16)
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = kdf.derive(password)
iv = os.urandom(16)

# 加密文件内容
encrypted_data = aes_encrypt(key, iv, data)

# 将密码和IV写入新文件
key_file_name = 'key_' + os.path.splitext(os.path.basename(file_path))[0] + '.txt'
key_file_path = os.path.join(os.path.dirname(sys.argv[0]), key_file_name)
with open(key_file_path, 'wb') as f:
    f.write(password + b'\n')
    f.write(salt + b'\n')
    f.write(iv)

print(f"Key saved to {key_file_path}")

encrypted_file_name = 'encrypted_' + os.path.basename(file_path)
encrypted_file_path = os.path.join(os.path.dirname(sys.argv[0]), encrypted_file_name)
with open(encrypted_file_path, 'wb') as f:
    f.write(encrypted_data)

print(f"Encrypted data saved to {encrypted_file_path}")