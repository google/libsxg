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

#ifndef LIBSXG_SXG_SIGNER_LIST_H_
#define LIBSXG_SXG_SIGNER_LIST_H_

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <stdint.h>

#include "stdbool.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  X509* public_key;
  char* certificate_url;
} sxg_ecdsa_cert_t;

typedef struct {
  EVP_PKEY* public_key;
} sxg_ed25519_t;

typedef struct {
  char* name;
  time_t date;
  time_t expires;
  EVP_PKEY* private_key;
  char* validity_url;
  enum signer_algorithm {
    SXG_ECDSA,
    SXG_ED25519,
  } type;
  union cert_t {
    sxg_ecdsa_cert_t ecdsa;
    sxg_ed25519_t ed25519;
  } public_key;
} sxg_signer_t;

typedef struct {
  sxg_signer_t* signers;
  size_t size;
  size_t capacity;
} sxg_signer_list_t;

// Create empty signers. Never fails.
sxg_signer_list_t sxg_empty_signer_list();

// Releases all memory and contents of target.
void sxg_signer_list_release(sxg_signer_list_t* target);

// Appends new ecdsa signer to signer list. Copies the string parameters and
// increments the reference count of private_key & public_key.
// Returns true on success.
bool sxg_add_ecdsa_signer(const char* name, uint64_t date, uint64_t expires,
                          const char* validity_url, EVP_PKEY* private_key,
                          X509* public_key, const char* certificate_url,
                          sxg_signer_list_t* target);

// Appends new Ed25519 signer to signer list. Copies the string parameters and
// increments the reference count of private_key & public_key.
// Returns true on success.
// Note: Ed25519 signer does not use certificates, then Ed25519 signer does not
// require certificate_url.
bool sxg_add_ed25519_signer(const char* name, uint64_t date, uint64_t expires,
                            const char* validity_url, EVP_PKEY* private_key,
                            EVP_PKEY* public_key, sxg_signer_list_t* target);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_SXG_SIGNER_LISTS_H_
