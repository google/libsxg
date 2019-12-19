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

#ifndef LIBSXG_INTERNAL_SXG_HEADER_H_
#define LIBSXG_INTERNAL_SXG_HEADER_H_

#include <stdbool.h>

#include "libsxg/sxg_buffer.h"
#include "libsxg/sxg_header.h"

#ifdef __cplusplus
extern "C" {
#endif

// Generates data for SXG's signedHeader. Returns true on success.
bool sxg_header_serialize_cbor(const sxg_header_t* from, sxg_buffer_t* dst);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_INTERNAL_SXG_HEADER_H_
