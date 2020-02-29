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

#ifndef LIBSXG_SXG_ENCODED_RESPONSE_H_
#define LIBSXG_SXG_ENCODED_RESPONSE_H_

#include <stddef.h>

#include "sxg_raw_response.h"

#ifdef __cplusplus
extern "C" {
#endif

// Represents HTTP response header and payload.
// Header includes [:status, content-encoding, mi-sha256] parameters, and
// the payload is MICE encoded.
typedef struct {
  sxg_header_t header;
  sxg_buffer_t payload;
} sxg_encoded_response_t;

// Creates empty response. Never fails.
sxg_encoded_response_t sxg_empty_encoded_response();

// Encodes and generates encoded_response from raw_response with MICE encoding
// record size. Returns true on success.
bool sxg_encode_response(const size_t mi_record_size,
                         const sxg_raw_response_t* src,
                         sxg_encoded_response_t* dst);

// Releases memory of raw_response.
void sxg_encoded_response_release(sxg_encoded_response_t* target);

// Writes the header integrity into given buffer. Returns true on success.
bool sxg_write_header_integrity(const sxg_encoded_response_t* src,
                                sxg_buffer_t* target);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_SXG_ENCODED_RESPONSE_H_
