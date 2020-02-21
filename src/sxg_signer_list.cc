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

#include "libsxg/sxg_signer_list.hpp"

#include <iostream>
#include <string>

#include "libsxg/internal/sxg_sig.h"

namespace sxg {

Signer::Signer(std::string name, uint64_t date, uint64_t expires,
               std::string validity_url, EVP_PKEY* private_key,
               X509* public_key, std::string certificate_url)
    : name_(name),
      date_(date),
      expires_(expires),
      validity_url_(std::move(validity_url)),
      private_key_(private_key),
      type_(SXG_ECDSA),
      ecdsa_publickey_(public_key),
      ed25519_publickey_(nullptr),
      certificate_url_(std::move(certificate_url)) {
  EVP_PKEY_up_ref(private_key);
  X509_up_ref(public_key);
}

Signer::Signer(std::string name, uint64_t date, uint64_t expires,
               std::string validity_url, EVP_PKEY* private_key,
               EVP_PKEY* public_key)
    : name_(name),
      date_(date),
      expires_(expires),
      validity_url_(std::move(validity_url)),
      private_key_(private_key),
      type_(SXG_ECDSA),
      ecdsa_publickey_(nullptr),
      ed25519_publickey_(public_key) {
  EVP_PKEY_up_ref(private_key);
  EVP_PKEY_up_ref(ed25519_publickey_);
}

Signer::Signer(Signer&& original)
    : name_(original.name_),
      date_(original.date_),
      expires_(original.expires_),
      validity_url_(std::move(original.validity_url_)),
      private_key_(original.private_key_),
      type_(original.type_),
      ecdsa_publickey_(original.ecdsa_publickey_),
      ed25519_publickey_(original.ed25519_publickey_),
      certificate_url_(std::move(original.certificate_url_)) {
  original.validity_url_ = "";
  original.private_key_ = nullptr;
  original.ecdsa_publickey_ = nullptr;
  original.ed25519_publickey_ = nullptr;
  original.certificate_url_ = "";
}

Signer::Signer(const Signer& original)
    : name_(original.name_),
      date_(original.date_),
      expires_(original.expires_),
      validity_url_(original.validity_url_),
      private_key_(original.private_key_),
      type_(original.type_),
      ecdsa_publickey_(original.ecdsa_publickey_),
      ed25519_publickey_(original.ed25519_publickey_),
      certificate_url_(original.certificate_url_) {
  if (private_key_ != nullptr) {
    EVP_PKEY_up_ref(private_key_);
  }
  if (ecdsa_publickey_ != nullptr) {
    X509_up_ref(ecdsa_publickey_);
  }
  if (ed25519_publickey_ != nullptr) {
    EVP_PKEY_up_ref(ed25519_publickey_);
  }
}

Signer::~Signer() {
  if (private_key_ != nullptr) {
    EVP_PKEY_free(private_key_);
  }
  if (ecdsa_publickey_ != nullptr) {
    X509_free(ecdsa_publickey_);
  }
  if (ed25519_publickey_ != nullptr) {
    EVP_PKEY_free(ed25519_publickey_);
  }
}

void SignerList::AddEcdsaSigner(std::string name, uint64_t date,
                                uint64_t expires, std::string validity_url,
                                EVP_PKEY* private_key, X509* public_key,
                                std::string certificate_url) {
  signers_.emplace_back(name, date, expires, validity_url, private_key,
                        public_key, certificate_url);
}

void SignerList::AddEd25519Signer(std::string name, uint64_t date,
                                  uint64_t expires, std::string validity_url,
                                  EVP_PKEY* private_key, EVP_PKEY* public_key) {
  signers_.emplace_back(name, date, expires, validity_url, private_key,
                        public_key);
}

std::string Signer::GenerateSignature(
    const std::string& fallback_url,
    const std::string& serialized_headers) const {
  sxg_sig_t sig = sxg_empty_sig();
  sig.date = date_;
  sig.expires = expires_;

  bool success = sxg_sig_set_name(name_.c_str(), &sig) &&
                 sxg_sig_set_integrity("digest/mi-sha256-03", &sig) &&
                 sxg_sig_set_validity_url(validity_url_.c_str(), &sig);
  switch (type_) {
    case SXG_ECDSA:
      success = success && sxg_sig_set_cert_sha256(ecdsa_publickey_, &sig) &&
                sxg_sig_set_cert_url(certificate_url_.c_str(), &sig);
      break;
    case SXG_ED25519:
      success = success && sxg_sig_set_ed25519key(ed25519_publickey_, &sig);
      break;
    default:
      return "";
      break;
  }
  success = success &&
            sxg_sig_generate_sig(
                fallback_url.c_str(),
                reinterpret_cast<const uint8_t*>(serialized_headers.c_str()),
                serialized_headers.size(), private_key_, &sig);
  std::string signature(sxg_write_signature_size(&sig), '\0');
  sxg_write_signature(&sig, reinterpret_cast<uint8_t*>(&signature[0]));
  sxg_sig_release(&sig);

  return signature;
}

std::string SignerList::GenerateSignatures(
    const std::string& fallback_url,
    const std::string& serialized_headers) const {
  std::string result;
  for (const auto& signer : signers_) {
    result += signer.GenerateSignature(fallback_url, serialized_headers);
  }
  return result;
}

}  // namespace sxg
