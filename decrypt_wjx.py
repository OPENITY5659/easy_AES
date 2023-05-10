import os
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import datetime

# 获取当前系统时间
current_time = datetime.datetime.now()

# 设定过期时间为2023年6月10日00:00:00
expiration_time = datetime.datetime(2023, 6, 10, 0, 0, 0)

# 检查当前时间是否超过过期时间
if current_time >= expiration_time:
    # 如果超过过期时间，则自动销毁程序
    os.remove(__file__)
    
def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

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
if len(sys.argv) < 3:
    print("Usage: python script.py [key_file] [encrypted_file]")
    input("Press any key to exit...")
    sys.exit(1)

key_file_path = sys.argv[1]
encrypted_file_path = sys.argv[2]

try:
    # 读取密钥文件内容
    with open(key_file_path, 'rb') as f:
        password = f.readline().rstrip(b'\n')
        salt = f.readline().rstrip(b'\n')
        iv = f.read()

    # 读取加密文件内容
    with open(encrypted_file_path, 'rb') as f:
        encrypted_data = f.read()

    # 生成AES密钥
    key = generate_aes_key(password, salt)

    # 解密文件内容
    decrypted_data = aes_decrypt(key, iv, encrypted_data)

    # 写入解密后的数据到新文件
    decrypted_file_name = 'decrypted_' + os.path.splitext(os.path.basename(encrypted_file_path))[0] + '.exe'
    decrypted_file_path = os.path.join(os.path.dirname(sys.argv[0]), decrypted_file_name)
    with open(decrypted_file_path, 'wb') as f:
        f.write(decrypted_data)

    print(f"Decrypted data saved to {decrypted_file_path}")
except Exception as e:
    print(f"Error: {e}")
    input("Press any key to exit...")

input("Press any key to exit...")