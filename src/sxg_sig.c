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
#include <inttypes.h>
#include <openssl/evp.h>
#include <string.h>

#include "libsxg/internal/sxg_buffer.h"
#include "libsxg/internal/sxg_codec.h"

sxg_sig_t sxg_empty_sig() {
  static const sxg_sig_t sig = {
      .name = {.data = NULL, .size = 0, .capacity = 0},
      .cert_sha256 = {.data = NULL, .size = 0, .capacity = 0},
      .cert_url = {.data = NULL, .size = 0, .capacity = 0},
      .ed25519key = {.data = NULL, .size = 0, .capacity = 0},
      .date = 0,
      .expires = 0,
      .integrity = {.data = NULL, .size = 0, .capacity = 0},
      .sig = {.data = NULL, .size = 0, .capacity = 0},
      .validity_url = {.data = NULL, .size = 0, .capacity = 0}};
  return sig;
}

void sxg_sig_release(sxg_sig_t* target) {
  sxg_buffer_release(&target->name);
  sxg_buffer_release(&target->cert_sha256);
  sxg_buffer_release(&target->cert_url);
  sxg_buffer_release(&target->ed25519key);
  target->date = 0;
  target->expires = 0;
  sxg_buffer_release(&target->integrity);
  sxg_buffer_release(&target->sig);
  sxg_buffer_release(&target->validity_url);
}

bool sxg_sig_set_name(const char* name, sxg_sig_t* sig) {
  sxg_buffer_release(&sig->name);
  return sxg_write_string(name, &sig->name);
}

bool sxg_sig_set_cert_sha256(X509* certificate, sxg_sig_t* sig) {
  sxg_buffer_release(&sig->cert_sha256);
  return sxg_calculate_cert_sha256(certificate, &sig->cert_sha256);
}

bool sxg_sig_set_cert_url(const char* cert_url, sxg_sig_t* sig) {
  sxg_buffer_release(&sig->cert_url);
  return sxg_write_string(cert_url, &sig->cert_url);
}

bool sxg_sig_set_ed25519key(const EVP_PKEY* public_key, sxg_sig_t* sig) {
  sxg_buffer_release(&sig->ed25519key);
  size_t key_len;
  return (EVP_PKEY_get_raw_public_key(public_key, NULL, &key_len) == 1) &&
         sxg_buffer_resize(key_len, &sig->ed25519key) &&
         (EVP_PKEY_get_raw_public_key(public_key, sig->ed25519key.data,
                                      &key_len) == 1);
}

bool sxg_sig_set_integrity(const char* integrity, sxg_sig_t* sig) {
  sxg_buffer_release(&sig->integrity);
  return sxg_write_string(integrity, &sig->integrity);
}

bool sxg_sig_set_validity_url(const char* validity_url, sxg_sig_t* sig) {
  sxg_buffer_release(&sig->validity_url);
  return sxg_write_string(validity_url, &sig->validity_url);
};

bool sxg_sig_generate_sig(const char* fallback_url, const sxg_buffer_t* header,
                          EVP_PKEY* private_key, sxg_sig_t* sig) {
  if (sig->name.size == 0 || sig->integrity.size == 0 ||
      sig->validity_url.size == 0) {
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
  if (sig->cert_sha256.size == 0) {
    success = success && sxg_write_byte(0, &message);
  } else {
    success = success && sxg_write_byte(32, &message) &&
              sxg_write_buffer(&sig->cert_sha256, &message);
  }

  // 5.  The 8-byte big-endian encoding of the length in bytes of
  // "validity-url", followed by the bytes of "validity-url".
  success =
      success && sxg_write_int(sig->validity_url.size, 8, &message) &&
      sxg_write_bytes(sig->validity_url.data, sig->validity_url.size, &message);

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
  success = success && sxg_write_int(header->size, 8, &message) &&
            sxg_write_buffer(header, &message);

  // Generate sigature of the message.
  sxg_buffer_release(&sig->sig);
  success = success && sxg_evp_sign(private_key, &message, &sig->sig);
  sxg_buffer_release(&message);

  return success;
}

static bool sxg_write_structured_header_binary(const sxg_buffer_t* binary,
                                               sxg_buffer_t* target) {
  return sxg_write_byte('*', target) && sxg_base64encode(binary, target) &&
         sxg_write_byte('*', target);
}

static bool sxg_write_structured_header_string(const sxg_buffer_t* string,
                                               sxg_buffer_t* target) {
  return sxg_write_byte('"', target) && sxg_write_buffer(string, target) &&
         sxg_write_byte('"', target);
}

static bool sxg_write_structured_header_uint(uint64_t num,
                                             sxg_buffer_t* target) {
  char integer_buffer[22];
  const int nbytes =
      snprintf(integer_buffer, sizeof(integer_buffer), "%" PRIu64, num);

  assert(nbytes > 0);
  assert((size_t)nbytes + 1 <= sizeof(integer_buffer));

  return sxg_write_bytes((const uint8_t*)integer_buffer, nbytes, target);
}

bool sxg_write_signature(const sxg_sig_t* sig, sxg_buffer_t* dst) {
  if (sig->name.size == 0 || sig->integrity.size == 0 || sig->sig.size == 0 ||
      sig->validity_url.size == 0) {
    return false;
  }

  bool success = sxg_write_buffer(&sig->name, dst) && sxg_write_byte(';', dst);

  if (sig->cert_sha256.size != 0) {
    success = success && sxg_write_string("cert-sha256=", dst) &&
              sxg_write_structured_header_binary(&sig->cert_sha256, dst) &&
              sxg_write_byte(';', dst);

    success = success && sxg_write_string("cert-url=", dst) &&
              sxg_write_structured_header_string(&sig->cert_url, dst) &&
              sxg_write_byte(';', dst);
  } else if (sig->ed25519key.size != 0) {
    success = success && sxg_write_string("ed25519key=", dst) &&
              sxg_write_structured_header_binary(&sig->ed25519key, dst) &&
              sxg_write_byte(';', dst);
  }

  success = success && sxg_write_string("date=", dst) &&
            sxg_write_structured_header_uint(sig->date, dst) &&
            sxg_write_byte(';', dst);

  success = success && sxg_write_string("expires=", dst) &&
            sxg_write_structured_header_uint(sig->expires, dst) &&
            sxg_write_byte(';', dst);

  success = success && sxg_write_string("integrity=", dst) &&
            sxg_write_structured_header_string(&sig->integrity, dst) &&
            sxg_write_byte(';', dst);

  success = success && sxg_write_string("sig=", dst) &&
            sxg_write_structured_header_binary(&sig->sig, dst) &&
            sxg_write_byte(';', dst);

  return success && sxg_write_string("validity-url=", dst) &&
         sxg_write_structured_header_string(&sig->validity_url, dst);
}
