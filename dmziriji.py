from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import sys
import getopt
import os

_ENCRYPT = 1  # 加密模式为1，默认
_DECRYPT = 0  # 解密模式为0，非默认


def getkey(keypath=''):
    '''读取密钥，密钥应该长16位，即16bytes'''
    if keypath == '':
        keypath = 'example.kkey'
    f = open(keypath, 'rb')
    key = f.read()
    return key


def getfile(path=''):
    '''读取文件，返回一个描述符和文件名'''

    if path == '':
        path = input()
    print("待读取的文件：",end="")
    print(path)
    f = open(path, 'rb')
    name = path.split('\\')[-1]
    return f, name


def main(argv):
    opts, args = getopt.getopt(argv, 'hed:k:')
    mode = _ENCRYPT
    path = ''
    keypath=''
    print("参数：")
    print(opts)
    for opt, arg in opts:
        if opt == '-h':
            print("-d 待解密的文件")
            print("默认会输出到工作目录的\\明文\\中")
            print("-c 待加密的文件")
            print("默认会输出到工作目录的\\密文\\中")
            print("-k 密钥文件")
            print("默认会读取工作目录中的\"example.kkey\"")
            exit()
        if opt == '-d':
            path = arg
            print(arg)
            mode = _DECRYPT
        if opt == '-e':
            path = arg
            print(arg)
            mode = _ENCRYPT
        if opt == '-k':
            keypath = arg

    key=getkey(keypath)
    if(mode == _DECRYPT):
        f, name = getfile(path)
        ciphertext = f.read()
        decipher = AES.new(key, AES.MODE_ECB)
        plaintxt = decipher.decrypt(ciphertext)
        plaintxt = unpad(plaintxt, 16)
        print("文件名：",end="")
        print(name)
        print("明文：",end="")
        print(plaintxt)
        pass
    else:
        f, name = getfile(path)
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = f.read()
        plaintext = pad(plaintext, 16)
        ciphertext = cipher.encrypt(plaintext)
        print("文件名：",end="")
        print(name)
        print("密文：",end="")
        print(ciphertext)
        newname="jwmi-"+name
        newpath=os.getcwd()+'\\密文\\'+newname
        f=open(newpath,'wb')
        f.write(ciphertext)
        pass


if __name__ == '__main__':
    main(sys.argv[1:])
    # print(__name__)
