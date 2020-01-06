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

#ifndef LIBSXG_SXG_CERT_CHAIN_H_
#define LIBSXG_SXG_CERT_CHAIN_H_

#include <openssl/ct.h>
#include <openssl/ocsp.h>
#include <openssl/x509.h>
#include <stdbool.h>

#include "libsxg/sxg_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  X509* certificate;
  OCSP_RESPONSE* ocsp_response;
  sxg_buffer_t sct_list;
} sxg_cert_t;

typedef struct {
  sxg_cert_t* certs;
  size_t size;
  size_t capacity;
} sxg_cert_chain_t;

// Creates empty cert chain. Never fails.
sxg_cert_chain_t sxg_empty_cert_chain();

// Releases all memory and content of Cert-Chain.
void sxg_cert_chain_release(sxg_cert_chain_t* target);

// Writes Cert-Chain to dst. Returns true on success.
bool sxg_write_cert_chain_cbor(const sxg_cert_chain_t* chain,
                               sxg_buffer_t* dst);

// Extracts OCSP URL to buffer from specified X509 certificate.
bool sxg_extract_ocsp_url(X509* cert, sxg_buffer_t* dst);

// Sends request to the `io` and receieves and parses the response to `dst`.
bool sxg_execute_ocsp_request(BIO* io, const char* path, OCSP_CERTID* id,
                              OCSP_RESPONSE** dst);

// Fetches OCSP response from specified cert.
bool sxg_fetch_ocsp_response(X509* cert, X509* issuer, OCSP_RESPONSE** dst);

// Adds new certificate to the Cert-Chain. OCSP response and SCT list can
// be NULL. Returns true on success.
bool sxg_cert_chain_append_cert(X509* cert, OCSP_RESPONSE* ocsp_response,
                                const sxg_buffer_t* sct_list,
                                sxg_cert_chain_t* target);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_SXG_CERT_CHAIN_H_
