from des import *
from os import sys

if __name__ == '__main__':
    if(len(sys.argv) < 3):
        print("input your file and option(0/1)")
        exit()
    file_path = sys.argv[1]
    opt = eval(sys.argv[2])
    if(opt < 0 or opt > 1):
        print("0: encrypt, 1: decipter")
        exit()
    des = Des()
    des.des_file(file_path, opt)
