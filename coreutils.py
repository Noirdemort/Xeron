from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import requests


def getKeyFromUrl(url):
    r = requests.get(url)
    z = r.text
    k = z.find('-----END PUBLIC KEY-----')
    z = z[26:k]
    z = z.replace(' ', '\n')
    z = '-----BEGIN PUBLIC KEY-----' + z + '-----END PUBLIC KEY-----'
    return z


def encrypt(public_key, message):
    key = RSA.importKey(public_key)
    cipherKey = PKCS1_OAEP.new(key)
    encrypted_blocks = []
    for i in range(0, len(message), 128):
        msg = message[i:i+128]
        encrypted_data = cipherKey.encrypt(msg.encode())
        encrypted_blocks.append(intArrayToStr(encrypted_data))
    return "BREAK:HERE".join(encrypted_blocks)


def decrypt(private_key, encrypted_string):
    encrypted_blocks = encrypted_string.split('BREAK:HERE')
    key = RSA.importKey(private_key)
    cipherKey = PKCS1_OAEP.new(key)
    clearText = ""
    for block in encrypted_blocks:
        block = bytes(strToIntArray(block))
        decrypted_data = cipherKey.decrypt(block).decode()
        clearText += decrypted_data
    return clearText


def strToIntArray(arr):
    arr = arr.split(",")
    return [int(x) for x in arr]


def intArrayToStr(arr):
    return ",".join([str(x) for x in arr])
