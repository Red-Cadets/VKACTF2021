#!/usr/bin/env python3

from Crypto.Cipher import ARC4
from Crypto.Hash import SHA
from hashlib import pbkdf2_hmac, sha256
from binascii import unhexlify, hexlify
import os

banner = '''
                                     ███   █████     ███                      
                                     ░░░   ░░███     ░░░                       
  █████   ██████  ████████    █████  ████  ███████   ████  █████ █████  ██████ 
 ███░░   ███░░███░░███░░███  ███░░  ░░███ ░░░███░   ░░███ ░░███ ░░███  ███░░███
░░█████ ░███████  ░███ ░███ ░░█████  ░███   ░███     ░███  ░███  ░███ ░███████ 
 ░░░░███░███░░░   ░███ ░███  ░░░░███ ░███   ░███ ███ ░███  ░░███ ███  ░███░░░  
 ██████ ░░██████  ████ █████ ██████  █████  ░░█████  █████  ░░█████   ░░██████ 
░░░░░░   ░░░░░░  ░░░░ ░░░░░ ░░░░░░  ░░░░░    ░░░░░  ░░░░░    ░░░░░     ░░░░░░  
                                                                               
                                                                               
                                                                               
  ███                ██████                                                    
 ░░░                ███░░███                                                   
 ████  ████████    ░███ ░░░   ██████                                           
░░███ ░░███░░███  ███████    ███░░███                                          
 ░███  ░███ ░███ ░░░███░    ░███ ░███                                          
 ░███  ░███ ░███   ░███     ░███ ░███                                          
 █████ ████ █████  █████    ░░██████                                           
░░░░░ ░░░░ ░░░░░  ░░░░░      ░░░░░░                                            
                                                                               
                                                                               
                                                                               
         █████                           ███                                   
        ░░███                           ░░░                                    
  █████  ░███████    ██████   ████████  ████  ████████    ███████              
 ███░░   ░███░░███  ░░░░░███ ░░███░░███░░███ ░░███░░███  ███░░███              
░░█████  ░███ ░███   ███████  ░███ ░░░  ░███  ░███ ░███ ░███ ░███              
 ░░░░███ ░███ ░███  ███░░███  ░███      ░███  ░███ ░███ ░███ ░███              
 ██████  ████ █████░░████████ █████     █████ ████ █████░░███████              
░░░░░░  ░░░░ ░░░░░  ░░░░░░░░ ░░░░░     ░░░░░ ░░░░ ░░░░░  ░░░░░███              
                                                         ███ ░███              
                                                        ░░██████               
                                                         ░░░░░░                
'''
print(banner)
with open("key", "rb") as f:
    key = f.read()

with open("SuperSecretFlag.txt", "rb") as f:
    secret = f.read()

try:
    print("Password 1: ", end="")
    userInput1 = unhexlify(input().encode())
    print("Password 2: ", end="")
    userInput2 = unhexlify(input().encode())
except:
    print("Unhexlification error")
    exit()

if len(userInput1) >= 216 or len(userInput2) >= 216:
    print("Too long!")
    exit() 

if userInput1 == userInput2:
    print("Error! You should input different secrets!")
    exit() 
nonce = os.urandom(4).hex().encode()
nonce1 = pbkdf2_hmac('sha256', userInput1, b'salt', 100000, dklen=32) + nonce
nonce2 = pbkdf2_hmac('sha256', userInput2, b'salt', 100000, dklen=32) + nonce

tempkey1 = SHA.new(key+nonce1).digest()
tempkey2 = SHA.new(key+nonce2).digest()

round1 = ARC4.new(tempkey1)
firstEncryption = round1.encrypt(secret)

round2 = ARC4.new(tempkey2)
finalEncryption = round2.encrypt(firstEncryption)
print(hexlify(finalEncryption + nonce).decode())
