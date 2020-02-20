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

#ifndef LIBSXG_INTERNAL_SXG_BUFFER_H_
#define LIBSXG_INTERNAL_SXG_BUFFER_H_

#include "libsxg/sxg_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

// Extends buffer if it does not have enough memory for desired_margin *
// item_size. Does not touch `size` of the buffer.
bool sxg_ensure_free_capacity_internal(size_t size, size_t desired_margin,
                                       size_t default_capacity,
                                       size_t item_size, size_t* capacity,
                                       void** buffer);

// Extends buffer if it does not have enough memory for desired_margin*
// item_size. Does not touch `size` of the buffer.
bool sxg_ensure_buffer_free_capacity(size_t desired_margin,
                                     sxg_buffer_t* target);

// Write integer in big-endian format to .
void sxg_serialize_int(uint64_t num, int nbytes, uint8_t* dest);

// Prints the content of the buffer to stdout in a hexdump-like format.
void sxg_buffer_dump(const sxg_buffer_t* target);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_INTERNAL_SXG_BUFFER_H_
