**1.Find bug**
- ![image](https://user-images.githubusercontent.com/113702087/212836854-fae3a78f-59bb-49ab-8d83-876269394cd5.png)
- Bài này 32 bit nên ghidra để decompiler.
- Ta thấy được lỗi overflow khi buf[80] nhưng lại được nhập 140
- ![image](https://user-images.githubusercontent.com/113702087/212837412-320ebb95-f19a-48a7-af72-55c4feec0c32.png)
- ![image](https://user-images.githubusercontent.com/113702087/212837444-a4fd5cec-9ed5-4976-8a1d-49b627047467.png)
- check qua các hàm ta thấy jmp2 thực thi shell với điều kiện biến jmp = 1, arg1 = 0xcafebabe và arg1 + arg2 = 0x13371337 shell và jmp1 vơi arg1 = 0xdeadbeef giúp jmp++
- do đó cần thực thi jmp1 rồi mới thực thi được jmp2
- với điều kiện arg1 = 0xcafebabe và arg1 + arg2 = 0x13371337 thì thật vô lý khi 0xcafebabe > 0x13371337
- ![image](https://user-images.githubusercontent.com/113702087/212839569-240c991d-28d1-40b3-a9da-125f67400502.png)
- ta thấy arg1 + arg2 được đưa vào eax, và eax thì chỉ lưu trữ được tối đa 4 byte vậy nếu có 1 giá trị 0x0113371337 là 5 byte khi được lưu vào eax sẽ bị mất đi 1 byte và còn 0x13371337
- -> arg2 của jmp2 sẽ là 0x48385879

**2. Exploit**
- với 32 bit các arg để thực thi 1 hàm thì nằm trên stack và có dạng | địa chỉ trả về -> arg1 -> arg2 |
- sau khi tính offset của buf với saverip ta thấy chúng cách nhau 124 byte đo đó chỉ còn lại 16 byte để thực thi các hàm trên do vậy ta chỉ có thể ghi được 4 lần trên stack
- do đó ta cần thực theo thứ tự từ main ban đầu -> jmp1(arg) -> main -> jmp2(agr1, arg2)
- thực thi jmp1 và quay lại main
- ![image](https://user-images.githubusercontent.com/113702087/212840427-00c85980-6e70-4f98-b81f-b1c2e6a4f946.png)
- thực thi jmp2(arg1, arg2) đến đây thì địa chỉ trả về là gì cũng được vì đã thực thi được shell rồi
- ![image](https://user-images.githubusercontent.com/113702087/212840587-5acdbe86-6d2e-40a9-8933-508dd8e004d1.png)
- getshell
- ![image](https://user-images.githubusercontent.com/113702087/212841019-c9a2c326-b9a9-44f3-b948-b1acc9161f13.png)
