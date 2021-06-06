from sympy import Poly, symbols, ZZ
from Crypto.Util.number import isPrime
from sympy import invert, GF
from random import shuffle
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
import math


def isPowerOf2 (n):
    return (n & (n-1) == 0) and n != 0

def invert_poly(f, Factor, p):
    inv_poly = None
    if isPrime(p) == True:
        inv_poly = invert(f, Factor, domain=GF(p))
    elif isPowerOf2(p):
        inv_poly = invert(f, Factor, domain=GF(2))
        e = int(math.log(p, 2))
        for i in range(1, e):
            inv_poly = ((2 * inv_poly - f * inv_poly ** 2) % Factor).trunc(p)
    else:
        raise Exception("Cannot invert polynomial in Z_{}".format(p))
    return inv_poly


def generate_f(n, d, p, q):
    x = symbols('x')
    while True:
        coefficients = [1 for _ in range(d)]
        coefficients += [-1 for _ in range(d-1)]
        length = len(coefficients)
        coefficients += [0 for _ in range(length, n)]
        shuffle(coefficients)
        f = Poly(coefficients, x)
        try:
            fp = invert_poly(f, Poly(x ** n - 1, x).set_domain(ZZ), p)
        except:
            pass
        else:
            try:
                fq = invert_poly(f, Poly(x ** n - 1, x).set_domain(ZZ), q)
            except:
                pass
            else:
                return f, fp, fq
 
def generate_g_r(n, d):
    x = symbols('x')
    coefficients = [1 for _ in range(d)]
    coefficients += [-1 for _ in range(d)]
    length = len(coefficients)
    coefficients += [0 for _ in range(length, n)]
    shuffle(coefficients)
    g = Poly(coefficients, x)
    return g

def bytes_to_polynomial(n, s, p):
    m = int(s.hex(), 16)
    print(m)
    newM = []
    while m > 0:
        newM = [(m % p) - int(math.floor(p/2 - 0.00001))] + newM
        m //= p
    newPoly = [-1 for i in range(n - len(newM) )] + newM
    return Poly(newPoly[::-1], x) # reverse array to convert to little endian format 

def polynomial_to_bytes(m):
    number = 0
    for i, coef in enumerate(m):
        number += int((coef + 1) *(3 ** i))
    print(number)
    _n = hex(number)[2:]
    if len(_n) % 2 == 1:
        _n = "0" + _n
    return bytes.fromhex(_n)


#----------------- Static params -----------------#

n = 64
p = 3
q = 2 ** 16
df = 23
dg = 22
dr = 22
x = symbols('x')
Factor = Poly(x ** n - 1, x).set_domain(ZZ)

#--------- Private/public key generation ---------#

f, fp, fq = generate_f(n, df, p, q)
g = generate_g_r(n, dg)
r = generate_g_r(n, dr)
h = (p*fq*g % Factor).trunc(q)
print("h = ", h)  # Public key

#--------------- Message generation --------------#
with open("DESKey", "rb") as _file:
    DESKey = _file.read()
message = bytes_to_polynomial(n, DESKey, p)

#----- Encryption (symmetric key protection) -----#
ct = ((r*h + message) % Factor).trunc(q)
print("ciphertext = ",ct) # Encrypted DES-key

#---------------- FLAG protection ----------------#
symmetricСipher = DES.new(DESKey, DES.MODE_ECB)
with open("flag.txt", "rb") as _file:
    flag = _file.read()

print("Secret info: ", symmetricСipher.encrypt(pad(flag, 8)).hex())
