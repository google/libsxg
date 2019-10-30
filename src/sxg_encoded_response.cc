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

#include "libsxg/sxg_encoded_response.hpp"

#include <iostream>

#include "libsxg/internal/sxg_codec.h"
#include "libsxg/internal/sxg_header.h"
#include "libsxg/sxg_raw_response.hpp"

namespace sxg {

EncodedResponse EncodedResponse::Encode(const size_t mi_record_size,
                                        const RawResponse &src) {
  std::string digest_value = "mi-sha256-03=";
  static const size_t base_size = digest_value.size();
  digest_value.resize(digest_value.size() +
                      sxg_base64encode_size(sxg_sha256_size()));
  EncodedResponse result;
  result.header_ = src.header;
  result.header_.Append(":status", "200");

  size_t encoded_size = sxg_mi_sha256_size(src.payload.size(), mi_record_size);
  uint8_t proof[SHA256_DIGEST_LENGTH];
  result.payload_.resize(encoded_size);
  sxg_encode_mi_sha256(reinterpret_cast<const uint8_t *>(src.payload.data()),
                       src.payload.size(), mi_record_size,
                       reinterpret_cast<uint8_t *>(&result.payload_[0]), proof);
  result.header_.Append("content-encoding", "mi-sha256-03");

  sxg_base64encode(proof, SHA256_DIGEST_LENGTH,
                   reinterpret_cast<uint8_t *>(&digest_value[base_size]));
  result.header_.Append("digest", std::move(digest_value));
  return result;
}

std::string EncodedResponse::GetHeaderIntegrity() const {
  std::string header = header_.SerializeInCbor();
  uint8_t digest[SHA256_DIGEST_LENGTH];
  sxg_sha256(reinterpret_cast<const uint8_t *>(header.data()), header.size(),
             digest);
  std::string result = "sha256-";
  const size_t prefix_size = result.size();
  result.resize(result.size() + sxg_base64encode_size(sxg_sha256_size()));
  sxg_base64encode(digest, sxg_sha256_size(),
                   reinterpret_cast<uint8_t *>(&result[prefix_size]));
  return result;
}

}  // namespace sxg
