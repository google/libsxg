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

#ifndef LIBSXG_SXG_GENERATE_H_
#define LIBSXG_SXG_GENERATE_H_

#include <stdbool.h>

#include "sxg_buffer.h"
#include "sxg_encoded_response.h"
#include "sxg_signer_list.h"

#ifdef __cplusplus
extern "C" {
#endif

// Writes SXG payload to dst. Returns true on success.
bool sxg_generate(const char* fallback_url, const sxg_signer_list_t* signers,
                  const sxg_encoded_response_t* resp, sxg_buffer_t* dst);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_SXG_GENERATE_H_
