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

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>

#include "gtest/gtest.h"
#include "libsxg/internal/sxg_buffer.h"
#include "test_util.h"

namespace {

class CertChainTest : public ::testing::Test {
 protected:
  void SetUp() {
    cert_ = nullptr;
    issuer_ = nullptr;
  }
  void SetEcdsa256() {
    FILE* const certfile = fopen("testdata/ocsp_included.pem", "r");
    ASSERT_TRUE(certfile != nullptr);
    cert_ = PEM_read_X509(certfile, nullptr, nullptr, nullptr);
    issuer_ = PEM_read_X509(certfile, nullptr, nullptr, nullptr);
    fclose(certfile);
  };
  void SetBadCert() {
    FILE* const certfile = fopen("testdata/cert256.pem", "r");
    ASSERT_TRUE(certfile != nullptr);
    cert_ = PEM_read_X509(certfile, nullptr, nullptr, nullptr);
    issuer_ = PEM_read_X509(certfile, nullptr, nullptr, nullptr);
    fclose(certfile);
  };
  void TearDown() {
    if (cert_ != nullptr) {
      X509_free(cert_);
    }
    if (issuer_ != nullptr) {
      X509_free(issuer_);
    }
  }
  X509* cert_;
  X509* issuer_;
};

TEST_F(CertChainTest, ExtractOcspUri) {
  ASSERT_NO_FATAL_FAILURE(SetEcdsa256());
  sxg_buffer_t url = sxg_empty_buffer();

  EXPECT_TRUE(sxg_extract_ocsp_url(cert_, &url));
  EXPECT_EQ('\0', url.data[url.size - 1]);  // Expects null termination.
  url.size -= 1;                            // remove the null termination.
  ASSERT_EQ("http://ocsp.digicert.com", sxg_test::BufferToString(url));

  sxg_buffer_release(&url);
}

TEST_F(CertChainTest, SendRequest) {
  int fds[2];
  ASSERT_EQ(0, pipe(fds));
  BIO* mem = BIO_new_fd(fds[1], BIO_CLOSE);
  ASSERT_NO_FATAL_FAILURE(SetEcdsa256());
  OCSP_RESPONSE* result = nullptr;
  std::string buff(4096, '\0');
  const uint8_t kExpectedBody[] =
      "\x30\x6d\x30\x6b\x30\x69\x30\x67\x30\x65\x30\x0d\x06\x09\x60\x86\x48\x01"
      "\x65\x03\x04\x02\x01\x05\x00\x04\x20\x46\xbb\x3c\xe9\x41\x2a\x83\x6b\x58"
      "\x76\x3c\x1b\xbb\xc3\x77\x3b\x7a\x6d\xf6\xb9\x33\x6d\x28\x5f\x3c\x67\x31"
      "\xc0\x66\x4f\x9c\x05\x04\x20\x00\xa4\x4d\x30\x8a\xb1\x08\xec\xe9\x3c\x46"
      "\xe3\x10\xa5\x5b\x3d\xb5\xb2\xaa\xb1\x29\x0e\x87\xa2\xf7\x5a\x28\x26\xa8"
      "\x9c\x79\x02\x02\x10\x0e\xc1\x4e\x04\xdf\x1a\x21\x89\x45\x81\xc9\x63\x38"
      "\x28\xae\x97";
  std::string method, path, protocol;
  std::string content_type, ocsp_request;
  std::string content_length;
  size_t length;
  char separator[4];
  std::string body;

  // The OCSP transaction will fail because this test doesn't mock a response,
  // but we can still validate the request.
  // TODO(twifkak): Mock a valid OCSP "good" response for the cert.
  EXPECT_FALSE(sxg_execute_ocsp_request(
      mem, "/foobar", OCSP_cert_to_id(EVP_sha256(), cert_, issuer_), &result));
  EXPECT_LT(0, read(fds[0], &buff[0], 4096));
  std::stringstream bufstream(buff);
  bufstream >> method >> path >> protocol >> content_type >> ocsp_request >>
      content_length >> length;
  EXPECT_EQ("POST", method);
  EXPECT_EQ("/foobar", path);
  EXPECT_EQ("HTTP/1.0", protocol);
  EXPECT_EQ("Content-Type:", content_type);
  EXPECT_EQ("application/ocsp-request", ocsp_request);
  EXPECT_EQ("Content-Length:", content_length);
  bufstream.read(separator, 4);
  EXPECT_EQ(0, memcmp("\r\n\r\n", separator, 4));
  body.resize(length);
  bufstream.read(&body[0], length);
  EXPECT_EQ(0, memcmp(kExpectedBody, (const uint8_t*)body.c_str(), length));

  BIO_free(mem);
}

TEST_F(CertChainTest, FailedToExtractOcspUri) {
  ASSERT_NO_FATAL_FAILURE(SetBadCert());  // Does not contains ocsp information.
  sxg_buffer_t url = sxg_empty_buffer();

  EXPECT_FALSE(sxg_extract_ocsp_url(cert_, &url));

  sxg_buffer_release(&url);
}

TEST_F(CertChainTest, EmptyChain) {
  sxg_buffer_t result = sxg_empty_buffer();
  sxg_cert_chain_t chain = sxg_empty_cert_chain();
  sxg_write_cert_chain_cbor(&chain, &result);

  EXPECT_EQ("\x81\x67\xf0\x9f\x93\x9c\xe2\x9b\x93",
            sxg_test::BufferToString(result));
  sxg_cert_chain_release(&chain);
  sxg_buffer_release(&result);
}

// Below tests emit request to the *REAL* server.
// DO NOT include them in casual or daily tests.

TEST_F(CertChainTest, DISABLED_GetOcsp) {
  ASSERT_NO_FATAL_FAILURE(SetEcdsa256());
  OCSP_RESPONSE* ocsp = nullptr;
  EXPECT_TRUE(sxg_fetch_ocsp_response(cert_, issuer_, &ocsp));
  ASSERT_NE(nullptr, ocsp);
  OCSP_RESPONSE_free(ocsp);
}

TEST_F(CertChainTest, DISABLED_Generate) {
  ASSERT_NO_FATAL_FAILURE(SetEcdsa256());
  sxg_buffer_t result = sxg_empty_buffer();
  sxg_buffer_t sct_list = sxg_empty_buffer();
  sxg_cert_chain_t chain = sxg_empty_cert_chain();
  OCSP_RESPONSE* ocsp = nullptr;
  EXPECT_TRUE(sxg_fetch_ocsp_response(cert_, issuer_, &ocsp));
  EXPECT_TRUE(sxg_cert_chain_append_cert(cert_, ocsp, &sct_list, &chain));
  EXPECT_TRUE(sxg_cert_chain_append_cert(issuer_, nullptr, &sct_list, &chain));

  sxg_write_cert_chain_cbor(&chain, &result);

  EXPECT_LT(0u, result.size);
  sxg_cert_chain_release(&chain);
  sxg_buffer_release(&result);
}

}  // namespace
