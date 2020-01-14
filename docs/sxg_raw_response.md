# sxg\_raw\_response\_t

Represents HTTP response header and payload.
Header and payload are initially empty, and should be filled by the user.
For generating SXG, you need to get `sxg_encoded_response_t` object,
the only way to get a valid `sxg_encoded_response_t` is converting from
`sxg_raw_response_t` via `sxg_encode_response` API.

## Fields

You can read/write all field via `sxg_header` API and `sxg_buffer` API.

### sxg\_header\_t header

HTTP response header of SXG inner value.
Initially empty.

### sxg\_buffer\_t payload

Payload of HTTP response, it can be arbitrary binary.
Initially empty.

## Functions

### sxg\_raw\_response\_t sxg\_empty\_raw\_response()

Creates empty response.
Never fails.

#### Arguments

Nothing.

#### Returns

Empty `sxg_raw_response_t`.

#### Example

```c
sxg_raw_response_t resp = sxg_empty_raw_response();

// You can write via API.
sxg_header_append_string("Content-Type", "text/html", &resp.header);
sxg_write_string("<!DOCTYPE html><html lang='en'></html>", &resp.payload);
```

### void sxg\_raw\_response\_release(sxg\_raw\_response\_t\* target)

Releases memory of `sxg_raw_response_t`.
Never fails.

#### Arguments

- `target`: Target HTTP response to release memory.

#### Returns

Nothing.

#### Example

```c
sxg_raw_response_t resp = sxg_empty_response_t();
sxg_raw_response_release(&resp);
```
