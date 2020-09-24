#!/usr/bin/env python
# coding: utf-8

# E-mail: pajirsp@gmai.com
# 这份代码包含 DES 加密、解密。
# 在这份文件里，将可以选择文件，将原来的 DES 16轮改为8轮。

from random import randrange
import base64
import re
from des_data import *
from key import __KEY__

class Des:
    def __init__(self):
        return
        
    # IP置换，输入64位01字符串，输出64位01字符串
    def IP(self, s):
        assert len(s) == 64
        
        ret = ""
        for i in IP_table:
            ret = ret + s[i]
        return ret
    
    # IP逆置换，输入64位01字符串，输出64位01字符串
    def IP_rev(self, s):
        assert len(s) == 64
        
        ret = ""
        for i in IP_table_rev:
            ret = ret + s[i]
        return ret
    
    # IPC置换，输入64位01字符串，输出64位01字符串
    def IPC(self, s):
        assert len(s) == 64
        
        ret = ""
        for i in IPC_table:
            ret = ret + s[i]
        return ret
    
    # PC置换，输入56位01字符串，输出48位01字符串
    def PC(self, s):
        assert len(s) == 56
        
        ret = ""
        for i in PC_table:
            ret = ret + s[i]
        return ret
    
    # E扩展，输入32位01字符串，输出48位01字符串
    def E(self, s):
        assert len(s) == 32
        
        ret = ""
        for i in E_table:
            ret = ret + s[i]
        return ret
    
    # 异或，输入输出都是01字符串
    def str_xor(self, str1, str2):
        ret = ""
        for i in range(0, len(str1)):
            xor = int(str1[i],10)^int(str2[i],10)
            if xor == 1:
                ret += '1'
            else:
                ret += '0'
        return ret
    
    # 生成8个子密钥，输入64位01字符串，输出8*48位01字符串
    def createKeys(self, inKey):
        assert len(inKey) == 64
        
        outKey = []
        
        # IPC置换，64bits->56bits
        key1 = self.IPC(inKey)
        
        # 8轮移位
        for i in range(8):
            key1 = key1[LS[i]:28] + key1[0:LS[i]] + key1[LS[i]+28:56] + key1[28:LS[i]+28]
            # PC置换，56bits->48bits
            key2 = self.PC(key1)
                
            #附加子密钥
            outKey.append(key2)
            
        return outKey
    
    # S盒替换，输入48位01字符串，输出32位01字符串
    def S(self, s):
        assert len(s) == 48
        
        ret = ""
        k = 0
        for i in range(0, len(s), 6):
            s_tmp = s[i:i+6]
            row = int(s_tmp[0] + s_tmp[5], 2)
            col = int(s_tmp[1:5], 2)
            s_S = bin(S8[k][row*16 + col])[2:] # 将整数转换为二进制字符串
            for j in range(0,4-len(s_S)):   # 补齐至4位
                s_S = '0' + s_S
            ret += s_S
                
        return ret
    
    # P盒置换，输入32位01字符串，输出32位字符串
    def P(self, s):
        assert len(s) == 32
        
        ret = ""
        for i in P_table:
            ret += s[i]
        return ret
        
    # 一次加密或解密，密钥为8*48位01字符串，明文/密文为64位01字符串，opt为类型：0加密 1解密
    def des(self, inText, keys, opt): 
        # 初始IP置换
        text0 = self.IP(inText)
        # 将其分为左右两部分
        L = text0[:32]
        R = text0[32:]
        
        # 16轮运算(opt=0:(0,8,1), opt=1:(7,-1,-1)
        for i in range(7*opt, 8-9*opt, 1-opt*2):
            # 进入轮函数F
            # R扩展为48位
            R_E = self.E(R)
            # 取出当前循环所需要的子密钥
            key = keys[i]
            #异或
            s_xor = self.str_xor(key, R_E)
            # S盒替换
            s_S = self.S(s_xor)
            # P盒置换
            s_P = self.P(s_S)
            # L与轮函数F结果异或
            s_xor2 = self.str_xor(s_P, L)
            #L R结果
            L = R
            R = s_xor2
        
        #IP逆置换
        outText = self.IP_rev(R + L)
        
        return outText
    
    # 将字符串转换为0101串，全部16位
    def stringToBit(self, s):
        return ''.join([bin(ord(c)).replace('0b', '').zfill(16) for c in s])
    
    # 将字符串转换为0101串，依照UFT编码，专门转换密钥，避免添加0
    def stringToUFTBit(self, s):
        return ''.join([bin(ord(c)).replace('0b', '') for c in s])
    
    # 将0101串转换为字符串，全部16位
    def bitToString(self, s):
        return ''.join([chr(i) for i in [int(b, 2) for b in re.findall(r'.{16}', s)]])
    
    # 将01字符串补齐或压缩至64位（密钥）
    def make_64_bit_key(self, binText):
        length = len(binText)
        if length >= 64:
            return binText[:64]
        else:
            for i in range(64 - length):
                binText += '0'
        return binText
    
    # 将01字符串补齐为64位的整数倍（明文，密文）
    def make_64_bit_text(self, binText):
        length = len(binText)
        for i in range((64 - length % 64) % 64):
            binText += '0'
        return binText
    
    # 从对话框读取密钥
    def get_key(self):
        assert 0 < len(__KEY__) < 64
        return __KEY__
        
    # 文件处理，opt为类型：0加密 1解密
    def des_file(self, read_dir, opt):
        # 首先判断密钥不为空，函数里有"assert"来保证不为空
        key = self.get_key()
        # print(read_dir)
        input_text = ""
        output_text = ""
        # 读取明文
        try:
            f = open(read_dir, 'r', encoding = 'utf-8')
            input_text = f.read()
            print("成功读取" + read_dir)
            f.close()
        except IOError:
            print(read_dir + "读取失败")
            return 1
        # print(input_text)
        # 加密时转换明文
        if opt == 0:
            input_text = self.make_64_bit_text(self.stringToBit(input_text))
        
        # 密钥处理
        key = self.make_64_bit_key(self.stringToUFTBit(key))
        keys = self.createKeys(key)
        
        # CBC模式加密，初始向量IV设置为64位密钥
        tmp = re.findall(r'.{64}', input_text)
        Y = key
        Z = key
        for X in tmp:
            # 加密：加密前X与上一个加密结果Y异或
            # 解密：解密后与上一个密码Z异或
            if opt == 0:
                X = self.str_xor(X, Y)
            Y = self.des(X, keys, opt)
            if opt == 1:
                Y = self.str_xor(Y, Z)
                Z = X
            output_text += Y
            
        # 解密后转换为文本字符
        if opt == 1:
            output_text = self.bitToString(output_text)
        
        # 保存密文/明文
        try:
            write_dir = ''
            if opt == 0:
                write_dir = read_dir.replace('before', 'after', 1)
            else:
                write_dir = read_dir.replace('after', 'before', 1)
            f = open(write_dir, 'w', encoding = 'utf-8')
            f.write(output_text)
            print("已保存至" + write_dir)
            f.close()
        except IOError:
            print(write_dir + "打开失败！")
            return 1
        return 0
