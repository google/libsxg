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

#ifndef LIBSXG_INTERNAL_SXG_CODEC_H_
#define LIBSXG_INTERNAL_SXG_CODEC_H_

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns size of expected digest length (fixed).
inline size_t sxg_sha256_size() { return SHA256_DIGEST_LENGTH; }
inline size_t sxg_sha384_size() { return SHA384_DIGEST_LENGTH; }

// Writes SHA-hash of `src` into `dst`. Returns true on success.
bool sxg_sha256(const uint8_t* src, size_t length, uint8_t* dst);
bool sxg_sha384(const uint8_t* src, size_t length, uint8_t* dst);

// Returns size of expected buffer length to input size.
size_t sxg_base64encode_size(const size_t length);

// Writes base64 of byte array to `dst`. Returns true on success.
bool sxg_base64encode(const uint8_t* src, size_t length, uint8_t* dst);

size_t sxg_mi_sha256_size(const size_t length, const uint64_t record_size);

size_t sxg_mi_sha256_remainder_size(size_t size, uint64_t record_size);

// Writes `encoded` and `proof` with Merkle Integrity Content Encoding(MICE)
// of `src`. Returns true on success.
bool sxg_encode_mi_sha256(const uint8_t* src, size_t size, uint64_t record_size,
                          uint8_t* encoded,
                          uint8_t proof[SHA256_DIGEST_LENGTH]);

// Replaces `dst` with SHA256 of `cert`. Returns true on success.
bool sxg_calculate_cert_sha256(X509* cert, uint8_t* dst);

// Returns size of expected buffer length for evp sign.
size_t sxg_evp_sign_size(EVP_PKEY* private_key, const uint8_t* src,
                         size_t length);

// Replaces `dst` with signature of `src`. Returns the size of signature on
// success.
size_t sxg_evp_sign(EVP_PKEY* private_key, const uint8_t* src, size_t length,
                    uint8_t* dst);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_INTERNAL_SXG_CODEC_H_
