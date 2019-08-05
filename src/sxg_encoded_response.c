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

#include "libsxg/sxg_encoded_response.h"

#include "libsxg/internal/sxg_codec.h"
#include "libsxg/internal/sxg_header.h"

sxg_encoded_response_t sxg_empty_encoded_response() {
  static const sxg_encoded_response_t empty_response = {
      .header = {.entries = NULL, .size = 0, .capacity = 0},
      .payload = {.data = NULL, .size = 0, .capacity = 0},
  };
  return empty_response;
}

bool sxg_encode_response(const size_t mi_record_size,
                         const sxg_raw_response_t* src,
                         sxg_encoded_response_t* dst) {
  sxg_buffer_t digest_value = sxg_empty_buffer();
  uint8_t digest[SHA256_DIGEST_LENGTH];
  sxg_encoded_response_release(dst);

  bool success =
      sxg_header_copy(&src->header, &dst->header) &&
      sxg_encode_mi_sha256(&src->payload, mi_record_size, &dst->payload,
                           digest) &&
      sxg_header_append_string("content-encoding", "mi-sha256-03",
                               &dst->header) &&
      sxg_header_append_string(":status", "200", &dst->header) &&
      sxg_write_string("mi-sha256-03=", &digest_value) &&
      sxg_base64encode_bytes(digest, SHA256_DIGEST_LENGTH, &digest_value) &&
      sxg_header_append_buffer("digest", &digest_value, &dst->header);

  sxg_buffer_release(&digest_value);
  if (!success) {
    sxg_encoded_response_release(dst);
  }
  return success;
}

bool sxg_write_header_integrity(const sxg_encoded_response_t* src,
                                sxg_buffer_t* dst) {
  sxg_buffer_t cbor = sxg_empty_buffer();
  sxg_buffer_t hashed = sxg_empty_buffer();

  const bool success = sxg_header_serialize_cbor(&src->header, &cbor) &&
                       sxg_calc_sha256(&cbor, &hashed) &&
                       sxg_write_string("sha256-", dst) &&
                       sxg_base64encode(&hashed, dst);

  sxg_buffer_release(&cbor);
  sxg_buffer_release(&hashed);
  return success;
}

void sxg_encoded_response_release(sxg_encoded_response_t* target) {
  sxg_header_release(&target->header);
  sxg_buffer_release(&target->payload);
}
