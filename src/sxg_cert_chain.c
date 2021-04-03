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

#include "libsxg/sxg_cert_chain.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <stdint.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>

#include "libsxg/internal/sxg_buffer.h"
#include "libsxg/internal/sxg_cbor.h"
#include "libsxg/sxg_buffer.h"

sxg_cert_t sxg_empty_cert() {
  static const sxg_cert_t cert = {
      .certificate = NULL,
      .ocsp_response = NULL,
      .sct_list = {NULL, 0, 0},
  };
  return cert;
}

sxg_cert_chain_t sxg_empty_cert_chain() {
  static const sxg_cert_chain_t chain = {
      .certs = NULL, .size = 0, .capacity = 0};
  return chain;
}

static void sxg_cert_release(sxg_cert_t* target) {
  if (target == NULL) {
    return;
  }
  X509_free(target->certificate);
  OCSP_RESPONSE_free(target->ocsp_response);
  sxg_buffer_release(&target->sct_list);
  *target = sxg_empty_cert();
}

static bool ensure_free_capacity(size_t desired_margin,
                                 sxg_cert_chain_t* target) {
  return sxg_ensure_free_capacity_internal(
      target->size, desired_margin, 8, sizeof(sxg_cert_chain_t),
      &target->capacity, (void**)&target->certs);
}

void sxg_cert_chain_release(sxg_cert_chain_t* target) {
  for (size_t i = 0; i < target->size; ++i) {
    sxg_cert_release(&target->certs[i]);
  }
  OPENSSL_free(target->certs);
  *target = sxg_empty_cert_chain();
}

static AUTHORITY_INFO_ACCESS* extract_aia_info(X509_EXTENSION* ext) {
  const ASN1_OBJECT* const kAiaOid =
      OBJ_txt2obj("1.3.6.1.5.5.7.1.1", /*dont_search_names=*/1);
  if (ext == NULL || OBJ_cmp(X509_EXTENSION_get_object(ext), kAiaOid) != 0) {
    return NULL;
  }
  return (AUTHORITY_INFO_ACCESS*)X509V3_EXT_d2i(ext);
}

bool sxg_extract_ocsp_url(X509* cert, sxg_buffer_t* dst) {
  sxg_buffer_release(dst);
  if (cert == NULL) {
    return false;
  }
  const int extensions = X509_get_ext_count(cert);
  for (int i = 0; i < extensions; ++i) {
    AUTHORITY_INFO_ACCESS* const aia_info =
        extract_aia_info(X509_get_ext(cert, i));
    if (aia_info == NULL) {
      continue;
    }
    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(aia_info); ++i) {
      ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia_info, i);
      if (ad == NULL) {
        continue;
      }
      int ad_nid = OBJ_obj2nid(ad->method);
      switch (ad_nid) {
        case NID_ad_OCSP: {
          if (ad->location == NULL || ad->location->type != GEN_URI) {
            continue;
          }
          ASN1_IA5STRING* uri = ad->location->d.uniformResourceIdentifier;
          if (uri == NULL || uri->data == NULL || uri->length == 0) {
            continue;
          }
          const bool success = sxg_write_bytes(uri->data, uri->length, dst) &&
                               sxg_write_byte('\0', dst);
          AUTHORITY_INFO_ACCESS_free(aia_info);
          return success;
        }
        default:
          break;
      }
    }
    AUTHORITY_INFO_ACCESS_free(aia_info);
  }
  return false;
}

static bool wait_fd(int fd, bool read, bool write) {
  // We use select(2) here for portability in Linux and BSD.
  int rv;
  fd_set confds;
  FD_ZERO(&confds);
  FD_SET(fd, &confds);
  struct timeval tv;
  tv.tv_usec = 0;
  tv.tv_sec = 3;
  if (read) {
    rv = select(fd + 1, (void*)&confds, NULL, NULL, &tv);
  } else if (write) {
    rv = select(fd + 1, NULL, (void*)&confds, NULL, &tv);
  } else {
    rv = 1;
  }
  return rv != 0 &&  // Timeout on request.
         rv != -1;   // Select error.
}

static const long nanos_per_sec = 1000000000L;

// Sleeps for the given number of milliseconds.
static void sleep_ms(int ms) {
  long ns = ms * 1000000L;
  struct timespec req;
  req.tv_sec = ns / nanos_per_sec;
  req.tv_nsec = ns % nanos_per_sec;
  while (clock_nanosleep(CLOCK_MONOTONIC, /*flags=*/0, &req, &req))
    ;
}

bool sxg_execute_ocsp_request(BIO* io, const char* path, OCSP_CERTID* id,
                              OCSP_RESPONSE** dst) {
  int fd;
  if (BIO_get_fd(io, &fd) < 0) {  // Can't get connection fd.
    return false;
  }
  OCSP_REQ_CTX* const octx = OCSP_sendreq_new(io, path, NULL, -1);
  OCSP_REQUEST* const req = OCSP_REQUEST_new();
  bool success = OCSP_request_add0_id(req, id) &&
                 OCSP_REQ_CTX_set1_req(octx, req) && wait_fd(fd, false, true);
  // Delay with backoff and max retries. This avoids pegging the CPU in the
  // event of a local failure, and hammering the OCSP responder in the event of
  // a remote failure, per https://gist.github.com/sleevi/5efe9ef98961ecfb4da8
  // item 5.
  int tries = 0;
  int delay_ms = 100;
  while (success) {
    switch (OCSP_sendreq_nbio(dst, octx)) {
      case -1:  // retry
        if (++tries <= 5) {
          sleep_ms(delay_ms);
          delay_ms *= 2;
          success = wait_fd(fd, BIO_should_read(io), BIO_should_write(io));
        } else {
          success = false;
        }
        continue;
      case 0:  // failure
        success = false;
      case 1:  // success
          ;
        // success == true already.
        // For both failure and success, break out of the loop.
    }
    break;
  }

  OCSP_REQUEST_free(req);
  OCSP_REQ_CTX_free(octx);
  return success;
}

static bool sxg_make_ocsp_session(const char* ocsp_url, char** path,
                                  BIO** connection) {
  char* host;
  char* port;
  int use_ssl;
  OCSP_parse_url(ocsp_url, &host, &port, path, &use_ssl);
  *connection = BIO_new_connect(host);

  bool success = *connection != NULL;
  if (success && port != NULL) {
    BIO_set_conn_port(*connection, port);
  }

  if (use_ssl == 1) {
    SSL_CTX* const ssl_ctx = SSL_CTX_new(SSLv23_client_method());
    if (ssl_ctx == NULL) {
      success = false;
      ;
    } else {
      SSL_CTX_set_mode(ssl_ctx, SSL_MODE_AUTO_RETRY);
      *connection = BIO_push(BIO_new_ssl(ssl_ctx, 1), *connection);
    }
  }

  OPENSSL_free(host);
  OPENSSL_free(port);
  return success;
}

bool sxg_fetch_ocsp_response(X509* cert, X509* issuer, OCSP_RESPONSE** dst) {
  sxg_buffer_t ocsp_url = sxg_empty_buffer();
  char* path = NULL;
  BIO* cbio = NULL;
  bool success =
      sxg_extract_ocsp_url(cert, &ocsp_url) &&
      sxg_make_ocsp_session((const char*)ocsp_url.data, &path, &cbio) &&
      BIO_do_connect(cbio) > 0 &&
      sxg_execute_ocsp_request(
          cbio, path, OCSP_cert_to_id(EVP_sha256(), cert, issuer), dst);

  sxg_buffer_release(&ocsp_url);
  OPENSSL_free(path);
  BIO_free(cbio);
  return success;
}

bool sxg_cert_chain_append_cert(X509* cert, OCSP_RESPONSE* ocsp_response,
                                const sxg_buffer_t* sct_list,
                                sxg_cert_chain_t* target) {
  X509_up_ref(cert);
  if (!ensure_free_capacity(1, target)) {
    return false;
  }
  sxg_cert_t* const new_cert = &target->certs[target->size];
  new_cert->certificate = cert;
  new_cert->ocsp_response = ocsp_response;
  new_cert->sct_list = sxg_empty_buffer();
  sxg_buffer_copy(sct_list, &new_cert->sct_list);
  target->size++;
  return true;
}

static bool sxg_get_x509_serialized_size(X509* cert, size_t* size) {
  const int len = i2d_X509(cert, NULL);
  if (len <= 0) {
    return false;
  }
  *size = len;
  return true;
}

static bool sxg_serialize_x509(X509* cert, uint8_t* dst) {
  const int len = i2d_X509(cert, &dst);
  if (len <= 0) {
    return false;
  }
  return true;
}
static size_t sxg_cert_entries(const sxg_cert_t* cert) {
  return (cert->certificate != NULL ? 1 : 0) +
         (cert->ocsp_response != NULL ? 1 : 0) +
         (cert->sct_list.data != NULL ? 1 : 0);
}

static bool sxg_write_x509_cbor(X509* cert, sxg_buffer_t* dst) {
  size_t serialized_size;
  bool success =
      sxg_get_x509_serialized_size(cert, &serialized_size) &&
      sxg_write_bytes_cbor_header(serialized_size, dst) &&
      sxg_buffer_resize(dst->size + serialized_size, dst) &&
      sxg_serialize_x509(cert, dst->data + dst->size - serialized_size);
  return success;
}

static bool sxg_get_ocsp_response_serialized_size(OCSP_RESPONSE* ocsp,
                                                  size_t* size) {
  const int len = i2d_OCSP_RESPONSE(ocsp, NULL);
  if (len <= 0) {
    return false;
  }
  *size = len;
  return true;
}

static bool sxg_serialize_ocsp_response(OCSP_RESPONSE* ocsp, uint8_t* dst) {
  const int len = i2d_OCSP_RESPONSE(ocsp, &dst);
  if (len <= 0) {
    return false;
  }
  return true;
}

static bool sxg_write_ocsp_response_cbor(OCSP_RESPONSE* ocsp,
                                         sxg_buffer_t* dst) {
  size_t serialized_size;
  bool success =
      sxg_get_ocsp_response_serialized_size(ocsp, &serialized_size) &&
      sxg_write_bytes_cbor_header(serialized_size, dst) &&
      sxg_buffer_resize(dst->size + serialized_size, dst) &&
      sxg_serialize_ocsp_response(ocsp,
                                  dst->data + dst->size - serialized_size);
  return success;
}

bool sxg_write_cert_chain_cbor(const sxg_cert_chain_t* chain,
                               sxg_buffer_t* dst) {
  static const char kMagicString[] = "📜⛓";
  bool success = sxg_write_array_cbor_header(chain->size + 1, dst) &&
                 sxg_write_utf8string_cbor(kMagicString, dst);

  for (size_t i = 0; i < chain->size && success; ++i) {
    sxg_cert_t* entry = &chain->certs[i];
    success = success &&
              sxg_write_map_cbor_header(sxg_cert_entries(entry), dst) &&
              entry->certificate != NULL;
    if (entry->sct_list.size > 0) {
      success = success && sxg_write_utf8string_cbor("sct", dst) &&
                sxg_write_bytes_cbor_header(entry->sct_list.size, dst) &&
                sxg_write_buffer(&entry->sct_list, dst);
    }
    success = success && sxg_write_utf8string_cbor("cert", dst) &&
              sxg_write_x509_cbor(entry->certificate, dst);
    if (entry->ocsp_response != NULL) {
      success = success && sxg_write_utf8string_cbor("ocsp", dst) &&
                sxg_write_ocsp_response_cbor(entry->ocsp_response, dst);
    }
  }
  return success;
}
