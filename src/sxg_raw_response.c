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

#include "libsxg/sxg_raw_response.h"

sxg_raw_response_t sxg_empty_raw_response() {
  static const sxg_raw_response_t empty_response = {
      .header = {.entries = NULL, .size = 0, .capacity = 0},
      .payload = {.data = NULL, .size = 0, .capacity = 0},
  };
  return empty_response;
}

void sxg_raw_response_release(sxg_raw_response_t* target) {
  sxg_header_release(&target->header);
  sxg_buffer_release(&target->payload);
}
