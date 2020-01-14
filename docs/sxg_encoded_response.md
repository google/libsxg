# sxg\_encoded\_response\_t

Represents HTTP response header and payload.
Header includes [:status, content-encoding, mi-sha256] parameters.
The payload is Merkle-Integrity-Content-Encoding(MICE) encoded.
You can find the specification [here](https://tools.ietf.org/html/draft-thomson-http-mice-03).

## Fields

You can read all fields via `sxg_header` API and `sxg_buffer` API.
Encoded data is not intended to be directly modified.
This instance should always be created via `sxg_encode_response` API.

### sxg\_header\_t header

Header of encoded http response.
It should always include [:status, content-encoding, mi-sha256] directives.

### sxg\_buffer\_t payload

Payload of HTTP response, it can be arbitrary binary.

## Functions

### sxg\_encoded\_response\_t sxg\_empty\_encoded\_response()

Creates empty response.
Never fails.

#### Arguments

Nothing.

#### Returns

Empty `sxg_encoded_response_t`.

### bool sxg\_encode\_response(const size\_t mi\_record\_size, const sxg\_raw\_response\_t\* src, sxg\_encoded\_response\_t\* dst)

Encodes and generates `encoded_response_t` from `raw_response_t` with MICE encoding record size.

#### Arguments

- `mi_record_size` : Record size of MICE.
- `src` : Raw HTTP response object.
- `dst` : Encoded HTTP response object to be replaced. Previous contents will be discarded.

#### Returns

Returns `true` on success.
On failure, `dst` will become empty.

#### Example

Do encoding on HTTP response.

```c
sxg_raw_response_t src = sxg_empty_raw_response();
sxg_encoded_response_t dst = sxg_empty_encoded_response();

sxg_encode_response(4096, &src, &dst);

sxg_raw_response_release(&src);
sxg_encoded_response_release(&dst);
```

### void sxg\_encoded\_response\_release(sxg\_encoded\_response\_t\* target)

Releases memory of `encoded_response_t`.

#### Arguments

- `target`: Target HTTP response to release memory.

#### Returns

Nothing.

### bool sxg\_write\_header\_integrity(const sxg\_encoded\_response\_t\* src, sxg\_buffer\_t\* target)

Writes the header integrity into given buffer.
The calculated integrity is appended to the end of the target `sxg_buffer`.

#### Arguments

- `src` : Encoded HTTP response whose header integrity is calculated.
- `target` : A buffer to store the integrity.

#### Returns

Returns `true` on success.
On fail, `target` may contain incomplete data.

#### Example

Print integrity.

```c
sxg_raw_response_t src = sxg_empty_raw_response();
sxg_encoded_response_t encoded = sxg_empty_encoded_response();
sxg_encode_response(4096, &src, &encoded);
sxg_buffer_t integrity = sxg_empty_buffer();

sxg_write_header_integrity(&encoded, &integrity);
sxg_write_byte('\0', &integrity);  // Null-termination.
printf("integrity: %s\n", integrity.data);

sxg_raw_response_release(&src);
sxg_encoded_response_release(&encoded);
sxg_buffer_release(&integrity);
```

