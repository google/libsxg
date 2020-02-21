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

#include "libsxg/internal/sxg_buffer.h"
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

  const size_t encoded_digest_size =
      sxg_base64encode_size(SHA256_DIGEST_LENGTH);

  bool success =
      sxg_header_copy(&src->header, &dst->header) &&
      sxg_buffer_resize(sxg_mi_sha256_size(src->payload.size, mi_record_size),
                        &dst->payload) &&
      sxg_encode_mi_sha256(src->payload.data, src->payload.size, mi_record_size,
                           dst->payload.data, digest) &&
      sxg_header_append_string("content-encoding", "mi-sha256-03",
                               &dst->header) &&
      sxg_header_append_string(":status", "200", &dst->header) &&
      sxg_write_string("mi-sha256-03=", &digest_value) &&
      sxg_ensure_buffer_free_capacity(encoded_digest_size, &digest_value) &&
      sxg_base64encode(digest, SHA256_DIGEST_LENGTH,
                       &digest_value.data[digest_value.size]);
  if (success) {
    digest_value.size += encoded_digest_size;
    success = success &&
              sxg_header_append_buffer("digest", &digest_value, &dst->header);
  }

  sxg_buffer_release(&digest_value);
  if (!success) {
    sxg_encoded_response_release(dst);
  }
  return success;
}

bool sxg_write_header_integrity(const sxg_encoded_response_t* src,
                                sxg_buffer_t* dst) {
  sxg_buffer_t cbor = sxg_empty_buffer();
  uint8_t digest[SHA256_DIGEST_LENGTH];

  const size_t encoded_integrity_size =
      sxg_base64encode_size(SHA256_DIGEST_LENGTH);
  const bool success =
      sxg_header_serialize_cbor(&src->header, &cbor) &&
      sxg_sha256(cbor.data, cbor.size, digest) &&
      sxg_write_string("sha256-", dst) &&
      sxg_ensure_buffer_free_capacity(
          sxg_base64encode_size(SHA256_DIGEST_LENGTH), dst) &&
      sxg_base64encode(digest, SHA256_DIGEST_LENGTH, &dst->data[dst->size]);
  if (success) {
    dst->size += encoded_integrity_size;
  }
  sxg_buffer_release(&cbor);
  return success;
}

void sxg_encoded_response_release(sxg_encoded_response_t* target) {
  sxg_header_release(&target->header);
  sxg_buffer_release(&target->payload);
}
