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

#ifndef LIBSXG_INTERNAL_SXG_SIG_H_
#define LIBSXG_INTERNAL_SXG_SIG_H_

#include <openssl/pem.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Represents SXG's signature header field values.
typedef struct sxg_sig {
  char* name;
  size_t name_size;

  uint8_t* cert_sha256;
  size_t cert_sha256_size;

  char* cert_url;
  size_t cert_url_size;

  uint8_t* ed25519key;
  size_t ed25519key_size;

  uint64_t date;
  uint64_t expires;

  char* integrity;
  size_t integrity_size;

  uint8_t* sig;
  size_t sig_size;

  char* validity_url;
  size_t validity_url_size;
} sxg_sig_t;

// Initializes empty sxg_sig_t data structure. Never fails.
sxg_sig_t sxg_empty_sig();

// Releases all memory and contents of target.
void sxg_sig_release(sxg_sig_t* target);

// Setters of sxg_sig structure. Contents are deep copied.
// Returns true on success.
bool sxg_sig_set_name(const char* name, sxg_sig_t* sig);
bool sxg_sig_set_cert_sha256(X509* certificate, sxg_sig_t* sig);
bool sxg_sig_set_cert_url(const char* cert_url, sxg_sig_t* sig);
bool sxg_sig_set_ed25519key(const EVP_PKEY* public_key, sxg_sig_t* sig);
bool sxg_sig_set_integrity(const char* integrity, sxg_sig_t* sig);
bool sxg_sig_set_validity_url(const char* validity_url, sxg_sig_t* sig);

// Fills up sig member with initialized and given parameters and private key.
// Returns true on success.
bool sxg_sig_generate_sig(const char* fallback_url, const uint8_t* header,
                          size_t header_size, EVP_PKEY* pkey, sxg_sig_t* sig);

// Returns size of signature.
size_t sxg_write_signature_size(const sxg_sig_t* sig);

// Writes serialized contents of signature with Structured Header format.
// Returns actual written size.
size_t sxg_write_signature(const sxg_sig_t* sig, uint8_t* dst);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_INTERNAL_SXG_SIG_H_
