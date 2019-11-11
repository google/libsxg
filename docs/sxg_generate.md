# sxg\_generate

SXG generation API.

## Functions

### bool sxg_generate(const char\* fallback\_url, const sxg\_signer\_list\_t\* signers, const sxg\_encoded\_response\_t\* resp, sxg\_buffer\_t\* dst)

Writes SXG payload to dst.

#### Arguments

- `fallback_url`: An URL which this SXG represents for.
- `signers`: Signers list to embed signatures to SXG.
- `resp`: Internal HTTP response header and body.
- `dst`: A buffer to store the result SXG.

#### Returns

Returns true on success.

#### Example

see [Quickstart](../README.md#Quickstart).
