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

#ifndef LIBSXG_SXG_RAW_RESPONSE_H_
#define LIBSXG_SXG_RAW_RESPONSE_H_

#include "sxg_buffer.h"
#include "sxg_header.h"

#ifdef __cplusplus
extern "C" {
#endif

// Represents a pair of HTTP response header and payload.
typedef struct {
  sxg_header_t header;
  sxg_buffer_t payload;
} sxg_raw_response_t;

// Creates empty response. Never fails.
sxg_raw_response_t sxg_empty_raw_response();

// Releases memory of raw_response.
void sxg_raw_response_release(sxg_raw_response_t* target);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_SXG_RAW_RESPONSE_H_
