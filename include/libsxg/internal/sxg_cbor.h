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

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns expected cbor initial bytes length.
size_t sxg_write_initial_bytes_size(uint64_t length);

// Writes cbor initial bytes to `target`.
void sxg_write_initial_bytes(uint8_t type_offset, uint64_t length,
                             uint8_t* target);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_INTERNAL_SXG_
