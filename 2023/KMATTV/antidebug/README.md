ENC(0xAB12DF34, 0x7B, 0x2D, 0x43)
-> stack có dạng
| stack | value |
|-----------|----------|
| esp | ebp |
| esp + 0x4 |  |
| esp + 0x8 | 0xAB12DF34 |
| esp + 0xc | 0x7B |
| esp + 0x10 | 0x2D |
| esp + 0x14 | 0x43 |
```
mov     eax, [ebp+0Ch]
add     eax, [ebp+10h]
add     eax, [ebp+8]
-> eax = 0x7B + 0x2D + 0xAB12DF34 = 0xab12dfdc
mov     ecx, [ebp+14h]
add     ecx, 0Ah
xor     ecx, [ebp+8]
-> ecx = (0x43 + 0xa)^0xAB12DF34 = 0xab12df79
add     eax, ecx
0xab12dfdc + 0xab12df79 = 0x15625bf55 nhưng eax chỉ lưu được 4 byte -> eax = 0x5625bf55
xor     eax, [ebp+8]
-> flag là : KCSC{0xfd376061}
```
