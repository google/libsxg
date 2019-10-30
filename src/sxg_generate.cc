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

#include "libsxg/sxg_generate.hpp"

#include <assert.h>

#include <cstring>
#include <iostream>  // DO NOT SUBMIT

#include "libsxg/internal/sxg_buffer.h"
#include "libsxg/sxg_encoded_response.hpp"
#include "libsxg/sxg_header.hpp"
#include "libsxg/sxg_signer_list.hpp"

namespace sxg {

static void write_int(uint64_t num, int nbytes, char* dst) {
  sxg_serialize_int(num, nbytes, reinterpret_cast<uint8_t*>(dst));
}

std::string Generate(const std::string& fallback_url, const SignerList& signers,
                     const EncodedResponse& resp) {
  static const std::string prefix = "sxg1-b3";
  std::string serialized_headers = resp.GetHeader().SerializeInCbor();

  std::string signature =
      signers.GenerateSignatures(fallback_url, serialized_headers);
  size_t estimated_size = prefix.size() + 1          // '\0'
                          + 2                        // length of fallback URL
                          + fallback_url.size() + 3  // length of signature
                          + 3  // length of serialized headers
                          + signature.size() + serialized_headers.size() +
                          resp.GetPayload().size();
  size_t wrote = 0;
  std::string sxg(estimated_size, '\0');

  // Step 1. "The ASCII characters "sxg1" followed by a 0 byte, to serve as a
  // file signature. This is redundant with the MIME type, and recipients that
  // receive both MUST check that they match and stop parsing if they don't."
  // [spec text] "Note: RFC EDITOR PLEASE DELETE THIS NOTE; The implementation
  // of the final RFC MUST use this file signature, but implementations of
  // drafts MUST NOT use it and MUST use another implementation-specific string
  // beginning with "sxg1-" and ending with a 0 byte instead." [spec text]
  memcpy(&sxg[wrote], prefix.c_str(), prefix.size());
  wrote += prefix.size();
  write_int(0, 1, &sxg[wrote++]);

  // Step 2. 2 bytes storing a big-endian integer "fallbackUrlLength".
  write_int(fallback_url.size(), 2, &sxg[wrote]);
  wrote += 2;

  // Step 3. "fallbackUrlLength" bytes holding a "fallbackUrl", which MUST be an
  // absolute URL with a scheme of "https".
  memcpy(&sxg[wrote], fallback_url.data(), fallback_url.size());
  wrote += fallback_url.size();

  // Step 4. 3 bytes storing a big-endian integer "sigLength".  If this is
  // larger than 16384 (16*1024), parsing MUST fail.
  write_int(signature.size(), 3, &sxg[wrote]);
  wrote += 3;

  // Step 5. 3 bytes storing a big-endian integer "headerLength". If this is
  // larger than 524288 (512*1024), parsing MUST fail.
  write_int(serialized_headers.size(), 3, &sxg[wrote]);
  wrote += 3;

  // Step 6. "sigLength" bytes holding the "Signature" header field's value
  // (Section 3.1).
  memcpy(&sxg[wrote], signature.data(), signature.size());
  wrote += signature.size();

  // Step 7. "headerLength" bytes holding "signedHeaders", the canonical
  // serialization (Section 3.4) of the CBOR representation of the response
  // headers of the exchange represented by the "application/ signed-exchange"
  // resource (Section 3.2), excluding the "Signature" header field.
  memcpy(&sxg[wrote], serialized_headers.data(), serialized_headers.size());
  wrote += serialized_headers.size();

  // Step 8. The payload body (Section 3.3 of [RFC7230]) of the exchange
  // represented by the "application/signed-exchange" resource.
  memcpy(&sxg[wrote], resp.GetPayload().data(), resp.GetPayload().size());
  wrote += resp.GetPayload().size();

  assert(wrote == estimated_size);
  return sxg;
}

}  // namespace sxg
