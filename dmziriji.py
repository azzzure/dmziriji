from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
key =b'\x07aaaaaaabaaaaaaa'
a=input()
print(a)
cipher = AES.new(key, AES.MODE_ECB)

plaintext =b'asdf'
plaintext=pad(plaintext,16)

ciphertext=cipher.encrypt(plaintext)
print(ciphertext)

decipher=AES.new(key, AES.MODE_ECB)
pplain=decipher.decrypt(ciphertext)
pplain=unpad(pplain,16)
print(pplain)