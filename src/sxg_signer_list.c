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

#include "libsxg/sxg_signer_list.h"

#include <assert.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include "libsxg/internal/sxg_buffer.h"
#include "libsxg/sxg_buffer.h"

sxg_signer_t sxg_empty_signer() {
  static const sxg_signer_t signer = {
      .name = NULL,
      .date = 0,
      .expires = 0,
      .private_key = NULL,
      .validity_url = NULL,
      .type = SXG_ECDSA,
      .public_key.ecdsa =
          {
              .public_key = NULL,
              .certificate_url = NULL,
          },
  };
  return signer;
}

void sxg_signer_release(sxg_signer_t* target) {
  OPENSSL_free(target->name);
  if (target->private_key != NULL) {
    EVP_PKEY_free(target->private_key);
  }
  OPENSSL_free(target->validity_url);
  switch (target->type) {
    case SXG_ECDSA:
      if (target->public_key.ecdsa.public_key != NULL) {
        X509_free(target->public_key.ecdsa.public_key);
      }
      OPENSSL_free(target->public_key.ecdsa.certificate_url);
      break;
    case SXG_ED25519:
      EVP_PKEY_free(target->public_key.ed25519.public_key);
      break;
    default:
      // Invalid keytype
      abort();
      break;
  }
  *target = sxg_empty_signer();
}

static bool ensure_free_capacity(size_t desired_margin,
                                 sxg_signer_list_t* target) {
  return sxg_ensure_free_capacity_internal(
      target->size, desired_margin, 8, sizeof(sxg_signer_t), &target->capacity,
      (void**)&target->signers);
}

sxg_signer_list_t sxg_empty_signer_list() {
  const sxg_signer_list_t signer_list = {
      .signers = NULL, .size = 0, .capacity = 0};
  return signer_list;
}

void sxg_signer_list_release(sxg_signer_list_t* target) {
  for (size_t i = 0; i < target->size; ++i) {
    sxg_signer_release(&target->signers[i]);
  }
  if (target->signers) {
    OPENSSL_free(target->signers);
  }
  *target = sxg_empty_signer_list();
}

bool sxg_add_ecdsa_signer(const char* name, uint64_t date, uint64_t expires,
                          const char* validity_url, EVP_PKEY* private_key,
                          X509* public_key, const char* certificate_url,
                          sxg_signer_list_t* target) {
  if (!ensure_free_capacity(1, target)) {
    return false;
  }
  sxg_signer_t* const new_signer = &target->signers[target->size];
  new_signer->name = OPENSSL_strdup(name);
  new_signer->validity_url = OPENSSL_strdup(validity_url);
  new_signer->public_key.ecdsa.certificate_url =
      OPENSSL_strdup(certificate_url);
  if (new_signer->name == NULL || new_signer->validity_url == NULL ||
      new_signer->public_key.ecdsa.certificate_url == NULL ||
      EVP_PKEY_up_ref(private_key) != 1) {
    OPENSSL_free(new_signer->name);
    OPENSSL_free(new_signer->validity_url);
    OPENSSL_free(new_signer->public_key.ecdsa.certificate_url);
    return false;
  }
  if (X509_up_ref(public_key) != 1) {
    OPENSSL_free(new_signer->name);
    OPENSSL_free(new_signer->validity_url);
    OPENSSL_free(new_signer->public_key.ecdsa.certificate_url);
    EVP_PKEY_free(private_key);
    return false;
  }
  new_signer->date = date;
  new_signer->expires = expires;
  new_signer->private_key = private_key;
  new_signer->type = SXG_ECDSA;
  new_signer->public_key.ecdsa.public_key = public_key;
  target->size++;
  return true;
}

bool sxg_add_ed25519_signer(const char* name, uint64_t date, uint64_t expires,
                            const char* validity_url, EVP_PKEY* private_key,
                            EVP_PKEY* public_key, sxg_signer_list_t* target) {
  if (!ensure_free_capacity(1, target)) {
    return false;
  }
  sxg_signer_t* const new_signer = &target->signers[target->size];
  new_signer->name = OPENSSL_strdup(name);
  new_signer->validity_url = OPENSSL_strdup(validity_url);
  if (new_signer->name == NULL || new_signer->validity_url == NULL ||
      EVP_PKEY_up_ref(private_key) != 1) {
    OPENSSL_free(new_signer->name);
    OPENSSL_free(new_signer->validity_url);
    return false;
  }
  if (EVP_PKEY_up_ref(public_key) != 1) {
    OPENSSL_free(new_signer->name);
    OPENSSL_free(new_signer->validity_url);
    EVP_PKEY_free(private_key);
    return false;
  }
  new_signer->date = date;
  new_signer->expires = expires;
  new_signer->private_key = private_key;
  new_signer->type = SXG_ED25519;
  new_signer->public_key.ed25519.public_key = public_key;
  target->size++;
  return true;
}
