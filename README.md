# Signed HTTP Exchange library

[![Build Status](https://travis-ci.org/google/libsxg.svg?branch=master)](https://travis-ci.org/google/libsxg)

## Introduction

Signed HTTP Exchange (SXG) is file format which contains an HTTP exchange
(request and response) signed by a publisher's origin.
https://tools.ietf.org/html/draft-yasskin-http-origin-signed-responses-06

If the publisher creates an SXG file with a valid signature, it will be treated
like a valid HTTP response regardless of the distribution channel.

This library is a minimal toolkit for handling SXG files.

## Requirements

- tested on OpenSSL 1.1.1c.

## Build \& Install

Simple cmake project.

```ShellSession
$ mkdir build
$ cd build
$ cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=path/to/usr -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_INSTALL_BINDIR=bin
$ make sxg
$ sudo make install
```

## Documentation

See [docs](docs/index.md).

## Quickstart

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

You can compile via:

```ShellSession
$ gcc sxgsample.c -lsxg -lcrypto
```
