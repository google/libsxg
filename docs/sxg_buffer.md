# sxg\_buffer\_t

A general variable sized buffer.

It should be initialized with `sxg_empty_buffer()`, otherwise you will touch uninitialized memory.
The memory space is not initially allocated.
The memory will be allocated on the first resize or write invocation and expanded as needed.
You must release memory via `sxg_buffer_release()`.

Memory is allocated via [OPENSSL\_malloc](https://www.openssl.org/docs/man1.1.1/man3/OPENSSL_malloc.html),
so you can change memory allocating functions by `CRYPTO_set_mem_functions`.

If you want to use `sxg_buffer_t` only, add `include` like

```c
#include <libsxg/sxg_buffer.h>
```

But in most cases, we recommend to include master header of this project like

```c
#include <libsxg.h>
```

## Fields

You can read all fields, but you should not modify any field directly except the
bytes pointed by the `data` pointer.
These fields should be modified via dedicated APIs.

### uint8\_t\* data

A memory fragment allocated for this buffer.
Initially NULL, in which case capacity and size must be 0.

### size\_t size

Size of buffer actually used.
Initially 0.
Every `sxg_write_*` API will increase this field.

### size\_t capacity

Allocated size of the buffer.
Initially 0.
Should be changed only when memory allocation happens.

## Functions

### sxg\_buffer\_t sxg\_empty\_buffer()

Creates a buffer with zero length and capacity. Never fails.

#### Arguments

Nothing.

#### Returns

Empty `sxg_buffer_t` structure with zero size and zero capacity.

#### Example

```c
/* You should initialize sxg_buffer_t with sxg_empty_buffer(). */
sxg_buffer_t buf = sxg_empty_buffer();
```

### void sxg\_buffer\_release(sxg\_buffer\_t\* target)

Releases memory of the buffer specified as `target`.
Never fails.

#### Arguments

- `target`: Target buffer to release memory.

#### Returns

Nothing.

#### Example

```c
sxg_buffer_t buf = sxg_empty_buffer();
/* You can call release function even if buffer is empty. */
sxg_buffer_release(&buf);
```

### bool sxg\_buffer\_resize(size\_t size, sxg\_buffer\_t\* target)

Resizes a buffer with specified length, contents are not initialized.

#### Arguments

- `size` : Desired buffer size. After success, you can access
  `target->data[0]` ~ `target->data[size-1]`.
- `target` : Buffer to be resized.

#### Returns

Returns `true` on success.
On fail, buffer will not be changed.

#### Example

Resizing buffer size to 100.

```c
sxg_buffer_t buf = sxg_empty_buffer();
sxg_buffer_resize(100, &buf);
for (int i = 0; i < 100; i++) {
  /* You can access data from [0]~[99]. */
  buf.data[i] = i;
}
sxg_buffer_release(&buf);
```

Load file contents into `sxg_buffer_t`.

```c
FILE* const fp = fopen("image.jpg", "rb");
assert(fp != NULL);
fseek(fp, 0L, SEEK_END);
const size_t file_size = ftell(fp);
sxg_buffer_t buf = sxg_empty_buffer();
sxg_buffer_resize(file_size, &buf);

rewind(fp);
const int nread = fread(buf->data, 1, file_size, fp);
assert(nread == file_size);  // Whole content of "image.jpg" will be read.

fclose(fp);
sxg_buffer_release(&buf);
```

### bool sxg\_write\_string(const char\* string, sxg\_buffer\_t\* target)

Appends string to the buffer. `string` must be null terminated.

#### Arguments

- `string` : Null-terminated string.
- `target` : Buffer to be modified.

#### Returns

Returns `true` on success.
On fail, `target` will not be changed.

#### Example

Store and print `Hello world`.

```c
sxg_buffer_t buf = sxg_empty_buffer();
sxg_write_string("Hello ", &buf);
sxg_write_string("world", &buf);

fwrite(buf.data, 1, buf.size, stdout);  // Prints `Hello world`.
printf("\n");
sxg_buffer_release(&buf);
```

### bool sxg\_write\_byte(uint8\_t byte, sxg\_buffer\_t\* target)

Appends one byte to the buffer.

#### Arguments

- `byte` : Byte to write.
- `target` : Buffer to be modified.

#### Returns

Returns `true` on success.
On fail, `target` will not be changed.

#### Example

Print `hello`.

```c
sxg_buffer_t buf = sxg_empty_buffer();
sxg_write_byte('h', &buf);
sxg_write_byte('e', &buf);
sxg_write_byte('l', &buf);
sxg_write_byte('l', &buf);
sxg_write_byte('o', &buf);

fwrite(buf.data, 1, buf.size, stdout);  // Prints `hello`.
printf("\n");
sxg_buffer_release(&buf);
```

### bool sxg\_write\_bytes(const uint8\_t\* bytes, size\_t size, sxg\_buffer\_t\* target)

Appends the specified bytes to the buffer.

#### Arguments

- `bytes` : Contents to write.
- `size` : Length of binary array data to write.
- `target` : Buffer to be modified.

#### Returns

Returns `true` on success.
On fail, `target` will not be changed.

#### Example

Make `sxg_buffer` from `std::string` (C++)

```cpp
std::string text("Hello C++ world");
sxg_buffer_t buf = sxg_empty_buffer();
sxg_write_bytes((const uint8_t*)test.data(), test.size(), &buf);

fwrite(buf.data, 1, buf.size, stdout);  // Prints `Hello C++ world`.
printf("\n");

sxg_buffer_release(&buf);
```

### bool sxg\_write\_buffer(const sxg\_buffer\_t\* follower, sxg\_buffer\_t\* target)

Appends the content of `follower` to the buffer.

#### Arguments

- `follower` : Buffer to write.
- `target` : Buffer to be modified.

#### Returns

Returns `true` on success.
On fail, `target` will not be changed.

#### Example

Print `Hello world`

```c
sxg_buffer_t hello = sxg_empty_buffer();
sxg_write_string("Hello ", &hello);
sxg_buffer_t world = sxg_empty_buffer();
sxg_write_string("world", &world);

sxg_write_buffer(&world, &hello);  // Concatenates `world` after `Hello `

fwrite(hello.data, 1, hello.size, stdout);  // Prints `Hello world`.
printf("\n");

sxg_buffer_release(&hello);
sxg_buffer_release(&world);
```

### bool sxg\_write\_int(uint64\_t num, int nbytes, sxg\_buffer\_t\* target)

Appends an integer in big-endian format with byte size `nbytes`.
`nbytes` must be in the range from 1 to 8.

#### Arguments

- `num` : Number to write.
- `nbytes` : Length of big-endian encoded number to write in bytes.
- `target` : Buffer to be modified.

#### Returns

Returns `true` on success.
On fail, `target` will not be changed.

#### Example

Write `UINT_MAX` to `sxg_buffer`.

```c
sxg_buffer_t buf = sxg_empty_buffer();
sxg_write_int(UINT_MAX, 4, &buf);

for (size_t i = 0; i < buf.size; i++) {
  printf("%02X", buf.data[i]);  // Prints `FFFFFFFF`.
}
printf("\n"):
sxg_buffer_release(&buf);
```

### bool sxg\_buffer\_copy(const sxg\_buffer\_t\* src, sxg\_buffer\_t\* dst)

Copies the contents of the buffer `src` to another buffer `dst`.
`dst` will be expanded as needed and overwritten with the copied content.
When length of `dst` is longer than `src`, this function will always succeed
because it does not invoke memory allocation.
Previous content of `dst` will be discarded.

#### Arguments

- `src` : Buffer to copy.
- `dst` : Buffer to be replaced.

#### Returns

Returns `true` on success.
On fail, `dst` will not be changed.

#### Example

Copy buffer `Document`.

```c
sxg_buffer_t buf1 = sxg_empty_buffer();
sxg_write_string("Document", &buf1);
sxg_buffer_t buf2 = sxg_empty_buffer();
sxg_buffer_copy(&buf1, &buf2);
sxg_buffer_release(&buf1);

// Even though buf1 is released, buf2 is available since `buf2` is deep copied.
fwrite(buf2.data, 1, buf2.size, stdout);  // Prints `Document`.
printf("\n");

sxg_buffer_release(&buf2);
```

