#!/usr/bin/env python3
#-*- coding:utf-8 -*-

from json import loads
from Crypto.Util.number import long_to_bytes, inverse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import os

class Group(object):
    def __init__(self, p, g, n):
       self.p = p
       self.g = g
       self.n = n

class Curve(object):
    """ Класс эллиптической кривой """
    def __init__(self, a, b, field):
        self.a = a
        self.b = b
        self.field = field

def point_neg(point):
    if point is None:
        return None
    x, y = point
    result = [x, -y % curve.field.p]
    return result

def point_add(point1, point2):
    if point1 is None:
        return point2
    if point2 is None:
        return point1
    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        m = (3 * x1 * x1 + curve.a) * inverse(2 * y1, curve.field.p)
    else:
        m = (y1 - y2) * inverse(x1 - x2, curve.field.p)
    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result =[x3 % curve.field.p,
              -y3 % curve.field.p]
    return result


def scalar_mult(k, point):
    if k % curve.field.n == 0 or point is None:
        return None
    if k < 0:
        return scalar_mult(-k, point_neg(point))
    result = None
    addend = point
    while k:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result


def ECDH(B, key):
    '''Elliptic-curve Diffie–Hellman (ECDH) key agreement protocol'''
    AB = scalar_mult(key,B)
    return hashlib.md5(long_to_bytes(int(AB[0]))).digest()
    
with open("flag.txt", "rb") as f:
    flag = f.read()
    
privateKey = 1067265257241045# то, что не должно было быть в таске, предполагалось дать указание, что секрет< 10**17

p = 73688320545818217223905980630685052067543196563414789199657738569

a = 1930284071043034966511196730157

b = 14943838357736369950522492908249619290393790926736268551962826292

g = (4596702642594596702775353863479252634452982770347689789112030411, 24508537272745787960258291691223973279118657715848319629535961983)

n = 24562773515272739074635326876894890635240717865300233479208274099

field = Group(p,g,n)
curve = Curve(a, b, field)
G = curve.field.g

publicKey = scalar_mult(privateKey, G)

banner = '''
    ________________  __  __
   / ____/ ____/ __ \/ / / /
  / __/ / /   / / / / /_/ / 
 / /___/ /___/ /_/ / __  /  
/_____/\____/_____/_/ /_/ 
'''
print(banner)
print("My public key: ", publicKey)

while True:
    try:
        your_input = loads(input())
        option = your_input["option"]
    except:
        print("Invalid json format or connection refused!")
        exit()
    if option == "encrypt":
        try:
            A_x = int(your_input["X"],16)
            A_y = int(your_input["Y"],16)
        except:
            print("You should spacify coordinates! (in hex)")
            exit()
        
        Plaintext = your_input["pl"].encode()
        A = [A_x, A_y]
        
        KEY = ECDH(A, privateKey)
        iv = os.urandom(16)
        cipher = AES.new(KEY, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(Plaintext,16))
        ans = {"ct":ct.hex(),"iv":iv.hex()}
        print(ans)
    elif option == "get_flag":
        KEY = hashlib.md5(long_to_bytes(privateKey)).digest()
        iv = os.urandom(16)
        cipher = AES.new(KEY,AES.MODE_CBC,iv)
        ct = cipher.encrypt(pad(flag,16))
        ans = {"ct":ct.hex(),"iv":iv.hex()}
        print((ans))
    else:
        print("Invalid options")
        exit()
