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

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "gtest/gtest.h"
#include "libsxg/sxg_buffer.h"
#include "test_util.h"

namespace sxg_test {

std::string BufferToString(const sxg_buffer_t& buf) {
  // Casting from uint8_t* to char* is legal because we confirmed char to have 8
  // bits.
  return std::string(reinterpret_cast<const char*>(buf.data), buf.size);
}

sxg_buffer_t StringToBuffer(const char* src) {
  sxg_buffer_t buf = sxg_empty_buffer();
  sxg_write_string(src, &buf);
  return buf;
}

X509* LoadX509Cert(const std::string& filename) {
  FILE* const certfile = fopen(filename.c_str(), "r");
  EXPECT_NE(nullptr, certfile) << "Failed to open privatekey";
  X509* cert = PEM_read_X509(certfile, 0, 0, NULL);
  fclose(certfile);
  return cert;
}

EVP_PKEY* LoadPrivateKey(const std::string& filepath) {
  FILE* const keyfile = fopen(filepath.c_str(), "r");
  EXPECT_NE(nullptr, keyfile) << "Could not open " << filepath;
  EVP_PKEY* private_key =
      PEM_read_PrivateKey(keyfile, nullptr, nullptr, nullptr);
  fclose(keyfile);
  return private_key;
}

EVP_PKEY* LoadPublicKey(const std::string& filepath) {
  FILE* certfile = fopen(filepath.c_str(), "r");
  EXPECT_NE(nullptr, certfile) << "Could not open " << filepath;
  char passwd[] = "";
  X509* cert = PEM_read_X509(certfile, 0, 0, passwd);
  fclose(certfile);
  EVP_PKEY* public_key = X509_extract_key(cert);
  X509_free(cert);
  return public_key;
}

EVP_PKEY* LoadEd25519Pubkey(const char* filepath) {
  FILE* keyfile = fopen(filepath, "r");
  EXPECT_NE(nullptr, keyfile) << "Could not open " << filepath;
  EVP_PKEY* public_key = PEM_read_PUBKEY(keyfile, nullptr, nullptr, nullptr);
  fclose(keyfile);
  return public_key;
}

}  // namespace sxg_test
