// Copyright 2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "libsxg/internal/sxg_sig.h"

#include <assert.h>
#include <openssl/evp.h>
#include <string.h>

#include "libsxg/internal/sxg_buffer.h"
#include "libsxg/internal/sxg_codec.h"
#include "libsxg/sxg_buffer.h"

sxg_sig_t sxg_empty_sig() {
  static const sxg_sig_t sig = {
      .name = NULL,
      .name_size = 0,
      .cert_sha256 = NULL,
      .cert_sha256_size = 0,
      .cert_url = NULL,
      .cert_url_size = 0,
      .ed25519key = NULL,
      .ed25519key_size = 0,
      .date = 0,
      .expires = 0,
      .integrity = NULL,
      .integrity_size = 0,
      .sig = NULL,
      .sig_size = 0,
  };
  return sig;
}

void sxg_sig_release(sxg_sig_t* target) {
  OPENSSL_free(target->name);
  target->name = NULL;
  OPENSSL_free(target->cert_sha256);
  target->cert_sha256 = NULL;
  OPENSSL_free(target->cert_url);
  target->cert_url = NULL;
  OPENSSL_free(target->ed25519key);
  target->ed25519key = NULL;
  target->date = 0;
  target->expires = 0;
  OPENSSL_free(target->integrity);
  target->integrity = NULL;
  OPENSSL_free(target->sig);
  target->sig = NULL;
  OPENSSL_free(target->validity_url);
  target->validity_url = NULL;
}

bool sxg_sig_set_name(const char* name, sxg_sig_t* sig) {
  sig->name_size = strlen(name);
  sig->name = OPENSSL_realloc(sig->name, sig->name_size + 1);
  if (sig->name == NULL) {
    return false;
  }
  strcpy(sig->name, name);
  return true;
}

bool sxg_sig_set_cert_sha256(X509* certificate, sxg_sig_t* sig) {
  sig->cert_sha256_size = sxg_sha256_size();
  sig->cert_sha256 = OPENSSL_realloc(sig->cert_sha256, sig->cert_sha256_size);
  if (sig->cert_sha256 == NULL) {
    return false;
  }
  return sxg_calculate_cert_sha256(certificate, sig->cert_sha256);
}

bool sxg_sig_set_cert_url(const char* cert_url, sxg_sig_t* sig) {
  sig->cert_url_size = strlen(cert_url);
  sig->cert_url = OPENSSL_realloc(sig->cert_url, sig->cert_url_size + 1);
  if (sig->cert_url == NULL) {
    return false;
  }
  strcpy(sig->cert_url, cert_url);
  return true;
}

bool sxg_sig_set_ed25519key(const EVP_PKEY* public_key, sxg_sig_t* sig) {
  size_t key_len;
  if (EVP_PKEY_get_raw_public_key(public_key, NULL, &key_len) != 1) {
    return false;
  }
  sig->ed25519key = OPENSSL_realloc(sig->ed25519key, key_len);
  if (sig->ed25519key == NULL) {
    return false;
  }
  return EVP_PKEY_get_raw_public_key(public_key, sig->ed25519key, &key_len) ==
         1;
}

bool sxg_sig_set_integrity(const char* integrity, sxg_sig_t* sig) {
  sig->integrity_size = strlen(integrity);
  sig->integrity = OPENSSL_realloc(sig->integrity, sig->integrity_size + 1);
  if (sig->integrity == NULL) {
    return false;
  }
  strcpy(sig->integrity, integrity);
  return true;
}

bool sxg_sig_set_validity_url(const char* validity_url, sxg_sig_t* sig) {
  sig->validity_url_size = strlen(validity_url);
  sig->validity_url =
      OPENSSL_realloc(sig->validity_url, sig->validity_url_size + 1);
  if (sig->validity_url == NULL) {
    return false;
  }
  strcpy(sig->validity_url, validity_url);
  return true;
};

bool sxg_sig_generate_sig(const char* fallback_url, const uint8_t* header,
                          size_t header_size, EVP_PKEY* private_key,
                          sxg_sig_t* sig) {
  if (sig->name == NULL || sig->name_size == 0 || sig->integrity == NULL ||
      sig->integrity_size == 0 || sig->validity_url == NULL ||
      sig->validity_url_size == 0) {
    return false;
  }

  // Generate a signature according to the specification of
  // https://tools.ietf.org/html/draft-yasskin-http-origin-signed-responses-05#section-3.5
  // Let "message" be the concatenation of the following byte strings. This
  // matches the [RFC8446] format to avoid cross protocol attacks if anyone uses
  // the same key in a TLS certificate and an exchange-signing certificate.
  sxg_buffer_t message = sxg_empty_buffer();

  // 1.  A string that consists of octet 32 (0x20) repeated 64 times.
  bool success = sxg_buffer_resize(64, &message);
  if (success) {
    memset(message.data, 0x20, 64);
  }

  // 2.  A context string: the ASCII encoding of "HTTP Exchange 1".
  success = success && sxg_write_string("HTTP Exchange 1 b3", &message);

  // 3.  A single 0 byte which serves as a separator.
  success = success && sxg_write_byte(0, &message);

  // 4.  If "cert-sha256" is set, a byte holding the value 32 followed by the 32
  // bytes of the value of "cert-sha256". Otherwise a 0 byte.
  if (sig->cert_sha256_size == 0) {
    success = success && sxg_write_byte(0, &message);
  } else {
    success =
        success && sxg_write_byte(32, &message) &&
        sxg_write_bytes(sig->cert_sha256, sig->cert_sha256_size, &message);
  }

  // 5.  The 8-byte big-endian encoding of the length in bytes of
  // "validity-url", followed by the bytes of "validity-url".
  success = success && sxg_write_int(sig->validity_url_size, 8, &message) &&
            sxg_write_bytes((uint8_t*)sig->validity_url, sig->validity_url_size,
                            &message);

  // 6.  The 8-byte big-endian encoding of "date".
  success = success && sxg_write_int(sig->date, 8, &message);

  // 7.  The 8-byte big-endian encoding of "expires".
  success = success && sxg_write_int(sig->expires, 8, &message);

  // 8.  The 8-byte big-endian encoding of the length in bytes of "requestUrl",
  // followed by the bytes of "requestUrl".
  success = success && sxg_write_int(strlen(fallback_url), 8, &message) &&
            sxg_write_string(fallback_url, &message);

  // 9.  The 8-byte big-endian encoding of the length in bytes of
  // "responseHeaders", followed by the bytes of "responseHeaders".
  success = success && sxg_write_int(header_size, 8, &message) &&
            sxg_write_bytes(header, header_size, &message);

  // Generate sigature of the message.
  sig->sig = OPENSSL_realloc(
      sig->sig, sxg_evp_sign_size(private_key, message.data, message.size));

  success = success && sig->sig != NULL;

  sig->sig_size =
      sxg_evp_sign(private_key, message.data, message.size, sig->sig);

  success = success && sig->sig_size > 0;
  sxg_buffer_release(&message);

  return success;
}

static size_t sxg_write_structured_header_binary_size(size_t size) {
  return 1 + sxg_base64encode_size(size) + 1;
}

static size_t sxg_write_structured_header_binary(const uint8_t* binary,
                                                 size_t length,
                                                 uint8_t* target) {
  size_t wrote = 0;
  memcpy(&target[wrote++], "*", 1);
  if (!sxg_base64encode(binary, length, &target[wrote])) {
    return false;
  }
  wrote += sxg_base64encode_size(length);
  memcpy(&target[wrote++], "*", 1);
  return wrote;
}

static size_t sxg_write_structured_header_string_size(size_t size) {
  return 1 + size + 1;
}

static size_t sxg_write_structured_header_string(const char* string,
                                                 size_t length,
                                                 uint8_t* target) {
  size_t wrote = 0;
  memcpy(&target[wrote++], "\"", 1);
  memcpy(&target[wrote], string, length);
  wrote += length;
  memcpy(&target[wrote++], "\"", 1);
  return wrote;
}

static size_t sxg_write_structured_header_uint_size(uint64_t num) {
  char integer_buffer[22];
  const int nbytes =
      snprintf(integer_buffer, sizeof(integer_buffer), "%" PRIu64, num);

  assert(nbytes > 0);
  assert((size_t)nbytes + 1 <= sizeof(integer_buffer));

  return strlen(integer_buffer);
}

static size_t sxg_write_structured_header_uint(uint64_t num, uint8_t* target) {
  char integer_buffer[22];
  const int nbytes =
      snprintf(integer_buffer, sizeof(integer_buffer), "%" PRIu64, num);

  assert(nbytes > 0);
  assert((size_t)nbytes + 1 <= sizeof(integer_buffer));

  memcpy(target, integer_buffer, nbytes);
  return nbytes;
}

size_t sxg_write_signature(const sxg_sig_t* const sig, uint8_t* dst) {
  if (sig->name_size == 0 || sig->integrity_size == 0 || sig->sig_size == 0 ||
      sig->validity_url_size == 0) {
    return false;
  }

  size_t wrote = 0;
  memcpy(&dst[wrote], sig->name, sig->name_size);
  wrote += sig->name_size;
  memcpy(&dst[wrote++], ";", 1);

  if (sig->cert_sha256_size != 0) {
    strcpy((char*)&dst[wrote], "cert-sha256=");
    wrote += strlen("cert-sha256=");
    wrote += sxg_write_structured_header_binary(
        sig->cert_sha256, sig->cert_sha256_size, &dst[wrote]);
    memcpy(&dst[wrote++], ";", 1);

    strcpy((char*)&dst[wrote], "cert-url=");
    wrote += strlen("cert-url=");
    wrote += sxg_write_structured_header_string(
        sig->cert_url, sig->cert_url_size, &dst[wrote]);
    memcpy(&dst[wrote++], ";", 1);
  } else if (sig->ed25519key_size != 0) {
    strcpy((char*)&dst[wrote], "ed25519key=");
    wrote += strlen("cert-url=");
    wrote += sxg_write_structured_header_binary(
        sig->ed25519key, sig->ed25519key_size, &dst[wrote]);
    memcpy(&dst[wrote++], ";", 1);
  }

  strcpy((char*)&dst[wrote], "date=");
  wrote += strlen("date=");
  wrote += sxg_write_structured_header_uint(sig->date, &dst[wrote]);
  memcpy(&dst[wrote++], ";", 1);

  strcpy((char*)&dst[wrote], "expires=");
  wrote += strlen("expires=");
  wrote += sxg_write_structured_header_uint(sig->expires, &dst[wrote]);
  memcpy(&dst[wrote++], ";", 1);

  strcpy((char*)&dst[wrote], "integrity=");
  wrote += strlen("integrity=");
  wrote += sxg_write_structured_header_string(sig->integrity,
                                              sig->integrity_size, &dst[wrote]);
  memcpy(&dst[wrote++], ";", 1);

  strcpy((char*)&dst[wrote], "sig=");
  wrote += strlen("sig=");
  wrote +=
      sxg_write_structured_header_binary(sig->sig, sig->sig_size, &dst[wrote]);
  memcpy(&dst[wrote++], ";", 1);

  strcpy((char*)&dst[wrote], "validity-url=");
  wrote += strlen("validity-url=");
  wrote += sxg_write_structured_header_string(
      sig->validity_url, sig->validity_url_size, &dst[wrote]);

  return wrote;
}

size_t sxg_write_signature_size(const sxg_sig_t* sig) {
  if (sig->name_size == 0 || sig->integrity_size == 0 || sig->sig_size == 0 ||
      sig->validity_url_size == 0) {
    return 0;
  }
  size_t estimated_size = sig->name_size + 1;

  if (sig->cert_sha256_size != 0) {
    estimated_size += strlen("cert-sha256=");
    estimated_size +=
        sxg_write_structured_header_binary_size(sig->cert_sha256_size) + 1;

    estimated_size += strlen("cert-url=");
    estimated_size +=
        sxg_write_structured_header_string_size(sig->cert_url_size) + 1;
  } else if (sig->ed25519key_size != 0) {
    estimated_size += strlen("ed25519key=");
    estimated_size +=
        sxg_write_structured_header_binary_size(sig->ed25519key_size) + 1;
  }

  estimated_size += strlen("date=");
  estimated_size += sxg_write_structured_header_uint_size(sig->date) + 1;

  estimated_size += strlen("expires=");
  estimated_size += sxg_write_structured_header_uint_size(sig->expires) + 1;

  estimated_size += strlen("integrity=");
  estimated_size +=
      sxg_write_structured_header_string_size(sig->integrity_size) + 1;

  estimated_size += strlen("sig=");
  estimated_size += sxg_write_structured_header_binary_size(sig->sig_size) + 1;

  estimated_size += strlen("validity-url=");
  estimated_size +=
      sxg_write_structured_header_string_size(sig->validity_url_size);

  return estimated_size;
}
