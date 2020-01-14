# Internal Document

Caution: These functions are not intended to used by the library's user, so the
interface may be changed without announcement.

Here is an incomplete list of internal functions.
Not every function will be documented.

## sxg\_buffer internals

You can use these functions by adding `#include <libsxg/internal/sxg_buffer.h>`.
You should not use these functions unless you know what you are doing.

### bool sxg\_write\_cbor\_header(size\_t length, sxg\_buffer\_t\* target)

Appends the CBOR header for a byte string (exposed for test).

#### Arguments

- `length` : Length of the byte string whose header to write.
- `target` : Buffer to be modified.

#### Returns

Returns `true` on success.
On fail, `target` will not be changed.

### bool sxg\_write\_bytes\_cbor(const uint8\_t\* bytes, size\_t length, sxg\_buffer\_t\* target)

Appends a byte string encoded in CBOR. Returns `true` on success.

#### Arguments

- `bytes` : Pointer to binary array data to write.
- `length` : Length of binary array data to write.
- `target` : Buffer to be modified.

#### Returns

Returns `true` on success.
On fail, `target` may be changed(only the header may be written).
