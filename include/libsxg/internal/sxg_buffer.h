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
// item_size.
bool sxg_ensure_free_capacity_internal(size_t size, size_t desired_margin,
                                       size_t default_capacity,
                                       size_t item_size, size_t* capacity,
                                       void** buffer);

// Appends an integer in big-endian format with nbytes. nbytes must be in the
// range from 1 to 8. Returns true on success.
bool sxg_write_int(uint64_t num, int nbytes, sxg_buffer_t* target);

// Prints the content of the buffer to stdout in a hexdump-like format.
void sxg_buffer_dump(const sxg_buffer_t* target);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_INTERNAL_SXG_BUFFER_H_
