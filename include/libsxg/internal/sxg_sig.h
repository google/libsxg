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

#include "libsxg/sxg_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

// Represents SXG's signature header field values.
typedef struct sxg_sig {
  sxg_buffer_t name;
  sxg_buffer_t cert_sha256;
  sxg_buffer_t cert_url;
  sxg_buffer_t ed25519key;
  uint64_t date;
  uint64_t expires;
  sxg_buffer_t integrity;
  sxg_buffer_t sig;
  sxg_buffer_t validity_url;
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
bool sxg_sig_generate_sig(const char* fallback_url, const sxg_buffer_t* header,
                          EVP_PKEY* pkey, sxg_sig_t* sig);

// Writes serialized contents of signature with Structured Header format.
// Returns true on success.
bool sxg_write_signature(const sxg_sig_t* sig, sxg_buffer_t* dst);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_INTERNAL_SXG_SIG_H_
