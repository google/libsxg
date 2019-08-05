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

#include "libsxg/internal/sxg_sig.h"

#include <cstdio>
#include <string>

#include "gtest/gtest.h"
#include "libsxg/internal/sxg_codec.h"
#include "libsxg/sxg_buffer.h"

namespace {

std::string BufferToString(const sxg_buffer_t& buf) {
  // Casting from uint8_t* to char* is legal because we confirmed char to have 8
  // bits.
  return std::string(reinterpret_cast<const char*>(buf.data), buf.size);
}

void FillSignature(sxg_buffer_t* buffer) {
  static const char sigKey[] = "sig=";
  char* point = strstr((char*)buffer->data, sigKey) + sizeof(sigKey) - 1;
  EXPECT_EQ('*', *point++);
  while (*point != '*') {
    *point++ = '%';
  }
}

TEST(SxgSig, ConstructAndRelease) {
  sxg_sig_t sig = sxg_empty_sig();
  sxg_sig_release(&sig);  // This is no-op.
}

X509* ReadCert(const std::string& filename) {
  FILE* const certfile = fopen(filename.c_str(), "r");
  EXPECT_NE(nullptr, certfile);
  X509* cert = PEM_read_X509(certfile, 0, 0, NULL);
  fclose(certfile);
  return cert;
}

EVP_PKEY* ReadPrivateKey(const std::string& filename) {
  FILE* const keyfile = fopen(filename.c_str(), "r");
  EXPECT_NE(nullptr, keyfile);
  EVP_PKEY* private_key = PEM_read_PrivateKey(keyfile, NULL, 0, NULL);
  fclose(keyfile);
  return private_key;
}

TEST(SxgSig, MakeSignature) {
  sxg_sig_t sig = sxg_empty_sig();
  X509* cert = ReadCert("testdata/cert256.pem");
  sxg_buffer_t header = sxg_empty_buffer();
  sxg_write_string("dummy_header", &header);
  EVP_PKEY* pkey = ReadPrivateKey("testdata/priv256.key");
  sxg_buffer_t output = sxg_empty_buffer();
  const std::string expected(
      "testname;cert-sha256=*WrpTHrnR9I9Cj+cizXTozEZB+BnjQKkRe8kKgme4iLU=*;"
      "cert-url=\"https://cert.test/"
      "cert.cbor\";date=0;expires=0;integrity=\"digest/"
      "mi-sha256-03\";sig=*%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
      "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*;validity-url=\"https://"
      "cert.test/validity.msg\"");

  EXPECT_TRUE(sxg_sig_set_name("testname", &sig));
  EXPECT_TRUE(sxg_sig_set_cert_sha256(cert, &sig));
  EXPECT_TRUE(sxg_sig_set_cert_url("https://cert.test/cert.cbor", &sig));
  EXPECT_TRUE(sxg_sig_set_integrity("digest/mi-sha256-03", &sig));
  EXPECT_TRUE(sxg_sig_set_validity_url("https://cert.test/validity.msg", &sig));
  EXPECT_TRUE(sxg_sig_generate_sig("https://sxg.test/", &header, pkey, &sig));
  EXPECT_TRUE(sxg_write_signature(&sig, &output));
  FillSignature(&output);
  EXPECT_EQ(expected, BufferToString(output));

  EVP_PKEY_free(pkey);
  X509_free(cert);
  sxg_buffer_release(&header);
  sxg_buffer_release(&output);
  sxg_sig_release(&sig);
}

}  // namespace
