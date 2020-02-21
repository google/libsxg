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

#ifndef LIBSXG_SXG_SIGNER_LIST_HPP_
#define LIBSXG_SXG_SIGNER_LIST_HPP_

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <string>
#include <vector>

namespace sxg {

class Signer {
 public:
  // For ecdsa signer.
  Signer(std::string name, uint64_t date, uint64_t expires,
         std::string validity_url, EVP_PKEY* private_key, X509* public_key,
         std::string certificate_url);

  // For ed25519 signer.
  Signer(std::string name, uint64_t date, uint64_t expires,
         std::string validity_url, EVP_PKEY* private_key, EVP_PKEY* public_key);

  Signer(Signer&& original);
  Signer(const Signer& original);
  Signer& operator=(const Signer& rhs);

  ~Signer();

  std::string GenerateSignature(const std::string& fallback_url,
                                const std::string& serialized_headers) const;

  std::string name_;
  time_t date_;
  time_t expires_;
  std::string validity_url_;
  EVP_PKEY* private_key_;

  enum signer_algorithm {
    SXG_ECDSA,
    SXG_ED25519,
  } type_;

  // Either of below must be NULL.
  X509* ecdsa_publickey_;
  EVP_PKEY* ed25519_publickey_;

  // In ed25519_publickey is not null, it must be NULL
  std::string certificate_url_;
};

class SignerList {
 public:
  // Appends new ecdsa signer to signer list.
  // Increments the reference count of private_key & public_key.
  void AddEcdsaSigner(std::string name, uint64_t date, uint64_t expires,
                      std::string validity_url, EVP_PKEY* private_key,
                      X509* public_key, std::string certificate_url);

  // Appends new Ed25519 signer to signer list.
  // Increments the reference count of private_key & public_key.
  // Note: Ed25519 signer does not use certificates, then Ed25519 signer does
  // not require certificate_url.
  void AddEd25519Signer(std::string name, uint64_t date, uint64_t expires,
                        std::string validity_url, EVP_PKEY* private_key,
                        EVP_PKEY* public_key);

  std::string GenerateSignatures(const std::string& fallback_url,
                                 const std::string& serialized_headers) const;

  size_t Size() const { return signers_.size(); }

 private:
  std::vector<Signer> signers_;
};

}  // namespace sxg

#endif  // LIBSXG_SXG_SIGNER_LISTS_HPP_
