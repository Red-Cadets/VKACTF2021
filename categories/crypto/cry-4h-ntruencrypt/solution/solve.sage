def convolution(f,g):
    return (f * g) % (x^n-1)

def balancedmod(f,q):
    g = list(((f[i] + q//2) % q) - q//2 for i in range(n))
    return Zx(g)

def invertmodprime(f,p):
    T = Zx.change_ring(Integers(p)).quotient(x^n-1)
    return Zx(lift(1 / T(f)))

def invertmodpowerof2(f,q):
    assert q.is_power_of(2)
    g = invertmodprime(f,2)
    while True:
        r = balancedmod(convolution(g,f),q)
        if r == 1: 
            return g
        g = balancedmod(convolution(g,2 - r),q)

def decrypt(ciphertext,secretkey):
    f,f3 = secretkey
    a = balancedmod(convolution(ciphertext,f),q)
    return balancedmod(convolution(a,f3),3)

def attack(publickey):
    recip3 = lift(1/Integers(q)(3))
    publickeyover3 = balancedmod(recip3 * publickey,q)
    M = matrix(2 * n)
    for i in range(n):
        M[i,i] = q
    for i in range(n):
        M[i+n,i+n] = 1
        c = convolution(x^i,publickeyover3)
        for j in range(n):
            M[i+n,j] = c[j]
    M = M.LLL()
    for j in range(2 * n):
        try:
            f = Zx(list(M[j][n:]))
            f3 = invertmodprime(f,3)
            return (f,f3)
        except:
            pass
    return (f,f)

def polynomial_to_bytes(m):
    number = 0
    for i, coef in enumerate(m):
        number += int((coef + 1) *(3 ^ i))
    _n = hex(number)[2:]
    if len(_n) % 2 == 1:
        _n = "0" + _n
    return bytes.fromhex(_n)

Zx.<x> = ZZ[]
n = 64
q = 2^16

publickey = -3086*x^63 + 27056*x^62 + 26207*x^61 - 7710*x^60 + 26797*x^59 - 30396*x^58 - 1353*x^57 - 10646*x^56 + 13474*x^55 + 17026*x^54 - 32739*x^53 - 621*x^52 - 14851*x^51 - 25052*x^50 - 9562*x^49 + 31900*x^48 - 21567*x^47 - 22019*x^46 - 28963*x^45 - 654*x^44 - 32168*x^43 - 19004*x^42 + 25489*x^41 + 11455*x^40 - 16134*x^39 + 1034*x^38 + 25037*x^37 + 3979*x^36 + 24083*x^35 + 6108*x^34 - 4831*x^33 - 5264*x^32 - 12683*x^31 + 17188*x^30 - 13162*x^29 - 4786*x^28 - 22753*x^27 + 14820*x^26 - 21201*x^25 - 17321*x^24 - 668*x^23 + 14267*x^22 + 5346*x^21 - 12711*x^20 + 3053*x^19 - 7062*x^18 + 1705*x^17 + 12947*x^16 + 6569*x^15 - 25920*x^14 + 31825*x^13 + 14049*x^12 + 686*x^11 + 18331*x^10 - 30291*x^9 + 12253*x^8 + 25146*x^7 + 21327*x^6 + 23484*x^5 - 4058*x^4 - 3157*x^3 + 7956*x^2 + 30268*x + 27064
privateKey = attack(publickey)

c = -15341*x^63 + 15815*x^62 + 10794*x^61 - 32601*x^60 - 25344*x^59 + 4620*x^58 - 9430*x^57 - 11502*x^56 + 2385*x^55 + 385*x^54 + 23875*x^53 + 2454*x^52 + 6277*x^51 + 25763*x^50 - 7467*x^49 - 17735*x^48 - 5233*x^47 - 10779*x^46 - 32222*x^45 - 5408*x^44 + 10333*x^43 + 20351*x^42 - 30220*x^41 - 18980*x^40 + 9951*x^39 + 25367*x^38 + 20095*x^37 - 20947*x^36 - 19638*x^35 - 23874*x^34 - 28013*x^33 - 13401*x^32 + 32328*x^31 - 16807*x^30 + 31226*x^29 + 17331*x^28 - 29073*x^27 - 19240*x^26 + 25041*x^25 - 5574*x^24 - 23434*x^23 - 13503*x^22 + 21135*x^21 - 21218*x^20 + 2321*x^19 - 16528*x^18 - 14298*x^17 - 8360*x^16 - 30292*x^15 - 8802*x^14 - 17750*x^13 + 12146*x^12 - 1371*x^11 + 20721*x^10 - 7016*x^9 - 20218*x^8 - 24381*x^7 + 22807*x^6 - 3142*x^5 - 3699*x^4 + 21201*x^3 + 2684*x^2 - 24376*x - 12353
m = decrypt(c, privateKey)
DESKey = polynomial_to_bytes(m.list()[::-1])
print(DESKey)
# b'u\x98\xb7\x1c\xa2P\xb7j'
