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

#ifndef LIBSXG_INTERNAL_SXG_CERT_CHAIN_H_
#define LIBSXG_INTERNAL_SXG_CERT_CHAIN_H_

#include <openssl/ct.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <stdbool.h>

#include "libsxg/sxg_cbor.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct sxg_cert_chain sxg_cert_chain_t;

// Writes Cert-Chain to dst. Returns true on success.
bool sxg_write_cert_chain_cbor(const sxg_cert_chain_t* chain,
                               sxg_buffer_t* dst);

// Returns OCSP URL length of specified X509 certificate.
size_t sxg_extract_ocsp_url_size(X509* cert);

// Extracts OCSP URL to buffer from specified X509 certificate.
bool sxg_extract_ocsp_url(X509* cert, uint8_t* dst);

// Sends request to `io` and receieves and parses the response to `dst`.
bool sxg_execute_ocsp_request(BIO* io, const char* path, OCSP_CERTID* id,
                              OCSP_RESPONSE** dst);

// Fetches OCSP response from specified X509 certificate.
bool sxg_fetch_ocsp_response(X509* cert, X509* issuer, OCSP_RESPONSE** dst);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_INTERNAL_SXG_CERT_CHAIN_H_
