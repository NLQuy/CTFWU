**1. Find bug**
- Dùng ida để xem cách hoạt động chương trình.
- ![image](https://user-images.githubusercontent.com/113702087/212818654-7b514c65-7ba7-409d-b985-845a0957d683.png)
- Ta thấy chương trình đọc file flag.txt vào biến flag và nhập username với password, login thành công thì ta được nhập 0x200 byte vào secret và in ra nó bằng printf.
- printf sẽ in cho đến khi gặp byte null + secret lại nằm trên flag cách nhau 0x200
- ![image](https://user-images.githubusercontent.com/113702087/212819594-7dfbdaea-783d-46ff-94ed-df3c99c707f4.png)
- vậy nếu ta nhập full secret thì ta có thể in được cả byte của flag ra.
- Ta có username = KCSC_4dm1n1str4t0r và passwd = wh3r3_1s_th3_fl4g
- ![image](https://user-images.githubusercontent.com/113702087/212820242-baf8901b-4135-42de-887a-91616d802924.png)

**2. Exploit**
![image](https://user-images.githubusercontent.com/113702087/212820377-b81d85c6-99bf-42e4-9133-98ea28ffd204.png)
