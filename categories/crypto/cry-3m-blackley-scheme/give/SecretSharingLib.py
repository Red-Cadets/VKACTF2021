from Crypto.Util.number import bytes_to_long, inverse, long_to_bytes
import random
from sss.MyUtils import check_for_linear_independence

p = 3513678996869745857

Team = [
    "admin",
    "Hygiea",
    "Pallas", 
    "Vesta"
]

def dot(a, b):
    return sum([a[i]*b[i] for i in range(len(a))])

def generateKeys(k, n, secret):
    Keys = []
    for i in range(n):
        hyperPlane = [random.randint(0, p) for _ in range(k)]
        d = ( (-1) * ( dot( hyperPlane, secret) ) ) % p
        hyperPlane.append(d)
        Keys.append(hyperPlane)
    return Keys

def SplitSecret(s, k):
    Length = len(s)
    Part = Length // k
    Secret = [bytes_to_long( s[Part*i:Part*(i+1)] ) for i in range(k - 1)]
    Secret.append(bytes_to_long(s[Part*(k-1):]))
    return Secret

def main():
    secret = open("secret.txt", "rb").read()
    k = n = len(Team)
    secretPoint = SplitSecret(secret, k)
    
    while True:
        K = generateKeys(k, n, secretPoint) # Parts of secret for everyone: [[a1, a2, ..., d], ...]
        if check_for_linear_independence(K, p) == True:
            break        

if __name__ == '__main__':
	main()

