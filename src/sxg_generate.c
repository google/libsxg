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

#include "libsxg/sxg_generate.h"

#include <assert.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <string.h>

#include "libsxg/internal/sxg_buffer.h"
#include "libsxg/internal/sxg_header.h"
#include "libsxg/internal/sxg_sig.h"

static bool write_signature(const sxg_signer_t* signer,
                            const char* fallback_url,
                            const sxg_buffer_t* serialized_headers,
                            sxg_buffer_t* dst) {
  sxg_sig_t sig = sxg_empty_sig();
  sig.date = signer->date;
  sig.expires = signer->expires;

  bool success = sxg_sig_set_name(signer->name, &sig) &&
                 sxg_sig_set_integrity("digest/mi-sha256-03", &sig) &&
                 sxg_sig_set_validity_url(signer->validity_url, &sig);
  switch (signer->type) {
    case SXG_ECDSA:
      success =
          success &&
          sxg_sig_set_cert_sha256(signer->public_key.ecdsa.public_key, &sig) &&
          sxg_sig_set_cert_url(signer->public_key.ecdsa.certificate_url, &sig);
      break;
    case SXG_ED25519:
      success = success && sxg_sig_set_ed25519key(
                               signer->public_key.ed25519.public_key, &sig);
      break;
    default:
      return false;
      break;
  }
  success = success &&
            sxg_sig_generate_sig(fallback_url, serialized_headers,
                                 signer->private_key, &sig) &&
            sxg_write_signature(&sig, dst);

  sxg_sig_release(&sig);
  return success;
}

static bool write_signatures(const sxg_signer_list_t* signers,
                             const char* fallback_url,
                             const sxg_buffer_t* serialized_headers,
                             sxg_buffer_t* dst) {
  bool success = true;
  for (size_t i = 0; i < signers->size && success; ++i) {
    if (i > 0) {
      success = success && sxg_write_byte(',', dst);
    }
    success = success && write_signature(&signers->signers[i], fallback_url,
                                         serialized_headers, dst);
  }
  return success;
}

bool sxg_generate(const char* fallback_url, const sxg_signer_list_t* signers,
                  const sxg_encoded_response_t* resp, sxg_buffer_t* dst) {
  sxg_buffer_t serialized_headers = sxg_empty_buffer();
  sxg_buffer_t signature = sxg_empty_buffer();

  if (!sxg_header_serialize_cbor(&resp->header, &serialized_headers) ||
      !write_signatures(signers, fallback_url, &serialized_headers,
                        &signature)) {
    sxg_buffer_release(&serialized_headers);
    sxg_buffer_release(&signature);
    return false;
  }

  assert(serialized_headers.size > 0);
  assert(signature.size > 0);

  // Step 1. "The ASCII characters "sxg1" followed by a 0 byte, to serve as a
  // file signature. This is redundant with the MIME type, and recipients that
  // receive both MUST check that they match and stop parsing if they don't."
  // [spec text] "Note: RFC EDITOR PLEASE DELETE THIS NOTE; The implementation
  // of the final RFC MUST use this file signature, but implementations of
  // drafts MUST NOT use it and MUST use another implementation-specific string
  // beginning with "sxg1-" and ending with a 0 byte instead." [spec text]
  sxg_buffer_release(dst);
  bool success = sxg_write_string("sxg1-b3", dst) && sxg_write_byte(0, dst);

  // Step 2. 2 bytes storing a big-endian integer "fallbackUrlLength".
  success = success && sxg_write_int(strlen(fallback_url), 2, dst);

  // Step 3. "fallbackUrlLength" bytes holding a "fallbackUrl", which MUST be an
  // absolute URL with a scheme of "https".
  success = success && sxg_write_string(fallback_url, dst);

  // Step 4. 3 bytes storing a big-endian integer "sigLength".  If this is
  // larger than 16384 (16*1024), parsing MUST fail.
  success = success && sxg_write_int(signature.size, 3, dst);

  // Step 5. 3 bytes storing a big-endian integer "headerLength". If this is
  // larger than 524288 (512*1024), parsing MUST fail.
  success = success && sxg_write_int(serialized_headers.size, 3, dst);

  // Step 6. "sigLength" bytes holding the "Signature" header field's value
  // (Section 3.1).
  success = success && sxg_write_buffer(&signature, dst);
  sxg_buffer_release(&signature);

  // Step 7. "headerLength" bytes holding "signedHeaders", the canonical
  // serialization (Section 3.4) of the CBOR representation of the response
  // headers of the exchange represented by the "application/ signed-exchange"
  // resource (Section 3.2), excluding the "Signature" header field.
  success = success && sxg_write_buffer(&serialized_headers, dst);
  sxg_buffer_release(&serialized_headers);

  // Step 8. The payload body (Section 3.3 of [RFC7230]) of the exchange
  // represented by the "application/signed-exchange" resource.
  return success && sxg_write_buffer(&resp->payload, dst);
}
