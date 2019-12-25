# libsxg - Signed HTTP Exchange (SXG) toolkit

## Overview of SXG

All specifications implemented in this library follow [this draft](https://tools.ietf.org/html/draft-yasskin-http-origin-signed-responses-06).
An SXG file consists of several parts.
The first part is `request URL` which represents the URL where the SXG payload is served.
The other essential parts are `Signature` and `Payload` described below.

### Signature

The `Signature` part contains the signature and several parameters encoded with [Structured Headers](https://tools.ietf.org/html/draft-ietf-httpbis-header-structure-10).
The parameters are below.

- `integrity`: Calculated checksum from MICE encoded HTTP payload.
- `validity-url`: A URL for validity information, it must be HTTPS and have the same origin as fallback-url.
- `date`: An Unix time when this signature's validity window starts.
- `expires`: A Unix time when the signature expires.
- `cert-url`: A URL containing the certificate for the signature. Any origin can serve the certificate.
- `cert-sha256`: An SHA-256 message digest of the certificate for this signature.
- `ed25519key`: A public key for the signature, it is required if signing key type is `Ed25519` and this parameter is mutually exclusive with `cert-url` and `cert-sha256`.
- `sig`: Signature made by private key using request URL, `cert-sha256`, `validity-url`, `date`, `expires` and serialized HTTP response header.

You can embed multiple signatures in a single SXG file.
Using multiple signatures gives you the flexibility of expiration or ways to obtain certificates.
You can configure the signers by `sxg_signer_list_t` related [functions](sxg_signer_list.md).

### Payload

`Payload` is a pair of HTTP header and body.
HTTP header is serialized using [CBOR encoding](https://tools.ietf.org/html/rfc7049).
Header must include `Digest` which is calculated from the body, `Content-Type` and `status`.
The body must be encoded with [mi-sha256](https://tools.ietf.org/html/draft-thomson-http-mice-03) to keep integrity of contents.
You can create the encoded payload by [sxg\_raw\_response\_t](sxg_raw_response.md) and [sxg\_encoded\_response\_t](sxg_encoded_response.md) and `sxg_encode_response` function.

## How to generate an SXG file

These steps describe how to use the library to make an SXG file.

1. Get HTTP response of your website to be signed.
2. Fill the response data into `sxg_raw_response_t` struct.
3. Call [sxg\_encode\_response](sxg_encoded_response.md#bool-sxg_encode_response_const-size_t-mi_record_size_const-sxg_raw_response_t_src_sxg_encoded_response_t_dst) function with your filled `sxg_raw_response_t` and produce `sxg_encoded_response_t`.
4. Prepare ECDSA key pair with certificate containing `CanSignHttpExchanges` extension.
5. Register the key pair and parameters as a signer in `sxg_signer_list_t` struct.
6. Call [sxg\_generate](sxg_generate.md) function to get SXG payload.

## API

- [sxg\_buffer\_t](sxg_buffer.md)
- [sxg\_encoded\_response\_t](sxg_encoded_response.md)
- [sxg\_header\_t](sxg_header.md)
- [sxg\_raw\_response\_t](sxg_raw_response.md)
- [sxg\_signer\_list\_t](sxg_signer_list.md)

### Miscellaneous

Some partial documents about internals at [internal](internals.md).
