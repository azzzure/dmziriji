from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import sys
import getopt
import os

_ENCRYPT = 1  # 加密模式为1，默认
_DECRYPT = 0  # 解密模式为0，非默认


def getkey():
    '''读取密钥，密钥应该长16位，即16bytes'''
    f = open('example.kkey', 'rb')
    key = f.read()
    return key


def getfile(path=''):
    '''读取文件，返回一个描述符和文件名'''

    if path == '':
        path = input()
    f = open(path, 'rb')
    name = path.split('\\')[-1]
    return f, name


def main(argv):
    opts, args = getopt.getopt(argv, 'hcd:k:')
    mode = _ENCRYPT
    path = ''
    for opt, arg in opts:
        if opt == '-h':
            print("go fuck yourself")
            exit()
        if opt == '-d':
            path = arg
            print(arg)
            mode = _DECRYPT
        if opt == '-c':
            path = arg
            print(arg)
            mode = _ENCRYPT

    if(mode == _DECRYPT):
        key = getkey()
        f, name = getfile(path)
        ciphertext = f.read()
        decipher = AES.new(key, AES.MODE_ECB)
        plaintxt = decipher.decrypt(ciphertext)
        plaintxt = unpad(plaintxt, 16)
        print(name)
        print(plaintxt)
        pass
    else:
        key = getkey()
        f, name = getfile(path)
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = f.read()
        plaintext = pad(plaintext, 16)
        ciphertext = cipher.encrypt(plaintext)
        print(name)
        print(ciphertext)
        newname="jwmi-"+name
        newpath=os.getcwd()+'\\密文\\'+newname
        f=open(newpath,'wb')
        f.write(ciphertext)
        pass


if __name__ == '__main__':
    main(sys.argv[1:])
    # print(__name__)
