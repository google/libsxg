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

#include "test_util.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "gtest/gtest.h"
#include "libsxg/sxg_buffer.h"

namespace sxg_test {

std::string BufferToString(const sxg_buffer_t& buf) {
  // Casting from uint8_t* to char* is legal because we confirmed char to have
  // 8 bits.
  return std::string(reinterpret_cast<const char*>(buf.data), buf.size);
}

sxg_buffer_t StringToBuffer(const char* src) {
  sxg_buffer_t buf = sxg_empty_buffer();
  sxg_write_string(src, &buf);
  return buf;
}

X509* LoadX509Cert(const std::string& filepath) {
  FILE* const certfile = fopen(filepath.c_str(), "r");
  if (certfile == nullptr) {
    std::cerr << "Could not open certificate from " << filepath;
    abort();
  }
  X509* cert = PEM_read_X509(certfile, nullptr, nullptr, nullptr);
  fclose(certfile);
  return cert;
}

EVP_PKEY* LoadPrivateKey(const std::string& filepath) {
  FILE* const keyfile = fopen(filepath.c_str(), "r");
  if (keyfile == nullptr) {
    std::cerr << "Could not open private key from " << filepath;
    abort();
  }
  EVP_PKEY* private_key =
      PEM_read_PrivateKey(keyfile, nullptr, nullptr, nullptr);
  fclose(keyfile);
  return private_key;
}

EVP_PKEY* LoadPublicKey(const std::string& filepath) {
  X509* cert = LoadX509Cert(filepath);
  if (cert == nullptr) {
    std::cerr << "Could not open public key from " << filepath;
    abort();
  }
  EVP_PKEY* public_key = X509_extract_key(cert);
  X509_free(cert);
  return public_key;
}

EVP_PKEY* LoadEd25519Pubkey(const std::string& filepath) {
  FILE* keyfile = fopen(filepath.c_str(), "r");
  if (keyfile == nullptr) {
    std::cerr << "Could not open Ed25519 public key from " << filepath;
    abort();
  }
  EVP_PKEY* public_key = PEM_read_PUBKEY(keyfile, nullptr, nullptr, nullptr);
  fclose(keyfile);
  return public_key;
}

}  // namespace sxg_test
