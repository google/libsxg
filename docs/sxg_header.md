# sxg\_header\_t

Represents HTTP header of SXG.
Used in both `sxg_raw_response_t` and `sxg_encoded_response_t`.

If you want to use `sxg_header_t` only, add

```c
#include <libsxg/sxg_header.h>
```

But in most cases, we recommend to include master header of this project like

```c
#include <libsxg.h>
```

## Fields

### sxg\_header\_t

Vector of `sxg_kvp_t`. You can read all fields, but you
should modify them via dedicated APIs.

#### sxg\_kvp\_t\* entries

Head pointer of key-value-pair vector of HTTP header.
Initially `NULL`.

#### size\_t size

Length of `entries` vector.
Initially 0.
Every `sxg_header_append` API will increment this field.

#### size\_t capacity

Allocated size of `entries` vector.
Initially 0.
Should be changed only when memory allocation happens.

### sxg\_kvp\_t

Element of `sxg_header_t` vector.

#### char\* key

Pointer to HTTP header's key string.
Always null-terminated.

#### sxg\_buffer\_t value

HTTP header's value byte array.

## Functions

### sxg\_header\_t sxg\_empty\_header()

Creates a header with zero length and capacity. Never fails.

#### Arguments

Nothing.

#### Returns

Empty `sxg_header_t` structure with zero size and zero capacity.

#### Example

```c
/* You should initialize sxg_header_t with sxg_empty_header(). */
sxg_header_t header = sxg_empty_header();
```

### void sxg\_header\_release(sxg\_header\_t\* target)

Releases entire contents of `sxg_header`.
Never fails.

#### Arguments

- `target`: Target header to release memory.

#### Returns

Nothing.

#### Example

```c
sxg_header_t header = sxg_empty_header();
/* You can call release function even if header is empty. */
sxg_header_release(&header);
```

### bool sxg\_header\_append\_buffer(const char\* key, const sxg\_buffer\_t\* value, sxg\_header\_t\* target)

Adds new key-value pair to the header.

#### Arguments

- `key` : HTTP header key string, e.g. "Content-Type". Must be null terminated. Content will be deep copied.
- `value` : HTTP header value stored in `sxg_buffer`, e.g. "text/html". Content will be deep copied.
- `target` : Header to be appended to.

#### Returns

Returns `true` on success.
On fail, header will not be changed.

#### Example

```c
sxg_header_t header = sxg_empty_header();

sxg_buffer_t value = sxg_empty_buffer();
sxg_write_string("None", &value);
sxg_header_append_buffer("Accept-Ranges", &value, &header);

sxg_buffer_release(&value);
sxg_header_release(&header);
```

### bool sxg\_header\_append\_string(const char\* key, const char\* value, sxg\_header\_t\* target)

Adds new key-value pair with null-terminated string value.

#### Arguments

- `key` : HTTP header key, e.g. "Content-Type". Must be null terminated. Content will be deep copied.
- `value` : HTTP header value, e.g. "text/html". Must be null terminated. Content will be deep copied.
- `target` : Header to be appended to.

#### Returns

Returns `true` on success.
On fail, header will not be changed.

#### Example

```c
sxg_header_t header = sxg_empty_header();

sxg_header_append_string("Content-Encoding", "gzip", &header);

sxg_header_release(&header);
```

### bool sxg\_header\_append\_integer(const char\* key, uint64\_t num, sxg\_header\_t\* target)

Adds new key-value pair with ASCII formatted integer value.

#### Arguments

- `key` : HTTP header key, e.g. "Content-Length". Must be null terminated. Content will be deep copied.
- `value` : HTTP header value, represented as integer.
- `target` : Header to be appended.

#### Returns

Returns `true` on success.
On fail, header will not be changed.

#### Example

```c
sxg_header_t header = sxg_empty_header();

sxg_header_append_integer("Content-Length", 12345, &header);

sxg_header_release(&header);
```

### bool sxg\_header\_copy(const sxg\_header\_t\* src, sxg\_header\_t\* dst)

Duplicates `sxg_header` with deep copy.
Previous content of `dst` will be released.

#### Arguments

- `src` : Header to copy.
- `dst` : Header to be replaced.

#### Returns

Returns `true` on success.
On fail, `dst` will not be changed.

#### Example

```c
sxg_header_t header1 = sxg_empty_header();
sxg_header_t header2 = sxg_empty_header();

sxg_header_append_integer("Content-Length", 12345, &header1);
sxg_header_copy(&header1, &header2);

// header2 will have {"Content-Length" : 12345}.

sxg_header_release(&header1);
sxg_header_release(&header2);
```

### bool sxg\_header\_merge(const sxg\_header\_t\* src, sxg\_header\_t\* target)

Appends all elements of `src` into `target`.
`src` will not be changed.

#### Arguments

- `src` : Header to copy.
- `dst` : Header to be replaced.

#### Returns

Returns `true` on success.
On fail, `target` may be partially merged.

```c
sxg_header_t header1 = sxg_empty_header();
sxg_header_t header2 = sxg_empty_header();

sxg_header_append_integer("Content-Length", 12345, &header1);
sxg_header_append_string("Content-Encoding", "gzip", &header2);
sxg_header_merge(&header1, &header2);

// header2 will have {"Content-Length" : 12345, "Content-Encoding" : "gzip"}.

sxg_header_release(&header1);
sxg_header_release(&header2);
```
