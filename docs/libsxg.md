# libsxg - Signed HTTP Exchange (SXG) toolkit

## SYNOPSIS

```c
#include <libsxg.h>

bool sxg\_buffer\_copy(const sxg\_buffer\_t\* src, sxg\_buffer\_t\* dst);
bool sxg\_buffer\_resize(size\_t size, sxg\_buffer\_t\* target);
bool sxg\_encode\_response(const size\_t mi\_record\_size, const sxg\_raw\_response\_t* src, sxg\_encoded\_response\_t* dst);
bool sxg\_header\_append\_buffer(const char\* key, const sxg\_buffer\_t\* value, sxg\_header\_t\* target);
bool sxg\_header\_append\_integer(const char\* key, uint64\_t num, sxg\_header_t\* target);
bool sxg\_header\_append\_string(const char\* key, const char\* value, sxg\_header\_t\* target);
bool sxg\_header\_copy(const sxg\_header\_t\* src, sxg\_header\_t\* dst);
bool sxg\_header\_merge(const sxg\_header\_t\* src, sxg\_header\_t\* target);
bool sxg\_write\_buffer(const sxg\_buffer\_t\* follower, sxg\_buffer\_t\* target);
bool sxg\_write\_byte(uint8\_t byte, sxg\_buffer\_t\* target);
bool sxg\_write\_bytes(const uint8\_t\* bytes, size\_t size, sxg\_buffer\_t\* target);
bool sxg\_write\_header\_integrity(const sxg\_encoded\_response\_t* src, sxg\_buffer\_t* target);
bool sxg\_write\_int(uint64\_t num, int nbytes, sxg\_buffer\_t\* target);
bool sxg\_write\_string(const char\* string, sxg\_buffer\_t\* target);
bool sxg_add\_ecdsa\_signer(const char\\* name, uint64\_t date, uint64\_t expires, const char\* validity\_url, EVP\_PKEY\* private\_key, X509\* public\_key, const char\* certificate\_url, sxg\_signer\_list\_t\* target);
bool sxg_add\_ed25519\_signer(const char\* name, uint64\_t date, uint64\_t expires, const char\* validity\_url, EVP\_PKEY\* private\_key, EVP\_PKEY\* public\_key, sxg\_signer\_list\_t\* target);
bool sxg_generate(const char\* fallback\_url, const sxg\_signer\_list\_t\* signers, const sxg\_encoded\_response\_t\* resp, sxg\_buffer\_t\* dst);
sxg\_buffer\_t sxg\_empty\_buffer();
sxg\_header\_t sxg\_empty\_header();
sxg\_raw\_response\_t sxg\_empty\_raw\_response();
sxg\_signer\_list\_t sxg\_empty\_signer\_list();
void sxg\_buffer\_release(sxg\_buffer\_t\* target);
void sxg\_encoded\_response\_release(sxg\_encoded\_response\_t* target);
void sxg\_header\_release(sxg\_header\_t\* target);
void sxg\_raw\_response\_release(sxg\_raw\_response\_t\* target);
void sxg\_signer\_list\_release(sxg\_signer\_list\_t\* target);
```

## RETURN VALUE

Returns true on success.

## EXAMPLE

```c
#include <assert.h>
#include <libsxg.h>
#include <openssl/crypto.h>
#include <openssl/pem.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

int main() {
  // Load keys.
  char passwd[] = "";
  FILE* keyfile = fopen("ecdsa.privkey", "r");
  assert(keyfile != NULL);
  EVP_PKEY* priv_key = PEM_read_PrivateKey(keyfile, NULL, NULL, NULL);
  fclose(keyfile);

  FILE* certfile = fopen("ecdsa.cert", "r");
  assert(certfile != NULL);
  X509* cert = PEM_read_X509(certfile, 0, 0, passwd);
  fclose(certfile);

  // Initialize signers.
  time_t now = time(NULL);
  sxg_signer_list_t signers = sxg_empty_signer_list();
  if (!sxg_add_ecdsa_signer(
          "my_signer", now, now + 60 * 60 * 24,
          "https://original.example.com/resource.validity.msg",
           priv_key, cert, "https://yourcdn.example.test/cert.cbor",
           &signers)) {
    printf("Failed to append signer.\n");
    return 1;
  }

  // Prepare contents.
  sxg_raw_response_t content = sxg_empty_raw_response();
  if (!sxg_header_append_string("content-type", "text/html; charset=utf-8",
                                &content.header)) {
    printf("Failed to append content-type header.\n");
    return 1;
  }
  if (!sxg_write_string("<!DOCTYPE html><html><body>Hello Sxg!</body></html>\n",
                        &content.payload)) {
    printf("Failed to set payload.\n");
    return 1;
  }

  // Encode contents.
  sxg_encoded_response_t encoded = sxg_empty_encoded_response();
  if (!sxg_encode_response(4096, &content, &encoded)) {
    printf("Failed to encode content.\n");
    return 1;
  }

  // Generate SXG.
  sxg_buffer_t result = sxg_empty_buffer();
  if (!sxg_generate("https://original.example.com/index.html", &signers,
                    &encoded, &result)) {
    printf("Failed to generate SXG.\n");
    return 1;
  }

  // Save SXG as a file.
  FILE* fp = fopen("hello.sxg", "w");
  assert(fp != NULL);
  size_t wrote = fwrite(result.data, result.size, 1, fp);
  assert(wrote == 1);
  fclose(fp);

  // Release resouces.
  EVP_PKEY_free(priv_key);
  X509_free(cert);
  sxg_signer_list_release(&signers);
  sxg_raw_response_release(&content);
  sxg_encoded_response_release(&encoded);
  sxg_buffer_release(&result);
  return 0;
}
```
