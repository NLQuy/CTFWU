**1. Find Bug**
 a, Xem qua chương trình bằng ida
  - ![image](https://user-images.githubusercontent.com/113702087/214768349-f4253b21-1fa8-4470-a735-24fb37c61be3.png)
  - main:
    + chương trình tạo 1 addr bằng shmat
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
