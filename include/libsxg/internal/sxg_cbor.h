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

#ifndef LIBSXG_INTERNAL_SXG_CBOR_H_
#define LIBSXG_INTERNAL_SXG_CBOR_H_

#include "libsxg/sxg_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

// Appends the initial bytes for a byte string (for internal use).
// Returns true on success.
bool sxg_write_bytes_cbor_header(uint64_t length, sxg_buffer_t* target);

// Appends the initial bytes for a utf-8 string (for internal use).
// Returns true on success.
bool sxg_write_utf8_cbor_header(uint64_t length, sxg_buffer_t* target);

// Appends the header for a map (visible for testing).
// Returns true on success.
bool sxg_write_map_cbor_header(uint64_t size, sxg_buffer_t* target);

// Appends the initial bytes for a array.
// Returns true on success.
bool sxg_write_array_cbor_header(uint64_t length, sxg_buffer_t* target);

// Appends utf-8 encoded string to the buffer. `string` must be null terminated.
// Returns true on success.
bool sxg_write_utf8string_cbor(const char* string, sxg_buffer_t* target);

// Appends a byte string encoded in CBOR. Returns true on success.
bool sxg_write_bytes_cbor(const uint8_t* bytes, size_t length,
                          sxg_buffer_t* target);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_INTERNAL_SXG_
