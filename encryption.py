from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import base64

# AES Encryption
def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

def aes_decrypt(ciphertext, key):
    data = base64.b64decode(ciphertext)
    iv = data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(data[AES.block_size:]), AES.block_size)
    return plaintext.decode('utf-8')

# DES Encryption
def des_encrypt(plaintext, key):
    cipher = DES.new(key, DES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), DES.block_size))
    return base64.b64encode(cipher.iv + ciphertext).decode('utf-8')

def des_decrypt(ciphertext, key):
    data = base64.b64decode(ciphertext)
    iv = data[:DES.block_size]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(data[DES.block_size:]), DES.block_size)
    return plaintext.decode('utf-8')

# RSA Encryption
def rsa_encrypt(plaintext, public_key):
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    ciphertext = cipher.encrypt(plaintext.encode())
    return base64.b64encode(ciphertext).decode('utf-8')

def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(RSA.import_key(private_key))
    plaintext = cipher.decrypt(base64.b64decode(ciphertext))
    return plaintext.decode('utf-8')

# RSA Key Generation
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key
