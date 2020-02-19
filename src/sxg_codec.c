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

#include "libsxg/internal/sxg_codec.h"

#include <assert.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <string.h>

#include "libsxg/internal/sxg_buffer.h"

bool sxg_sha256(const uint8_t* src, size_t length, uint8_t* dst) {
  return SHA256(src, length, dst) != NULL;
}

bool sxg_sha384(const uint8_t* src, size_t length, uint8_t* dst) {
  return SHA384(src, length, dst) != NULL;
}

size_t sxg_base64encode_size(const size_t length) {
  return 4 * ((length + 2) / 3);
}

bool sxg_base64encode(const uint8_t* src, size_t length, uint8_t* dst) {
  BUF_MEM* bptr;
  BIO* base64 = BIO_new(BIO_f_base64());
  if (base64 == NULL) {
    return false;
  }
  BIO* bmem = BIO_new(BIO_s_mem());
  if (bmem == NULL) {
    BIO_free(base64);
    return false;
  }
  base64 = BIO_push(base64, bmem);
  BIO_set_flags(base64, BIO_FLAGS_BASE64_NO_NL);  // We don't need following \n.

  bool success = BIO_write(base64, src, length) > 0 && BIO_flush(base64) > 0 &&
                 BIO_get_mem_ptr(base64, &bptr) > 0;
  if (success) {
    memcpy(dst, (const uint8_t*)bptr->data, bptr->length);
  }

  BIO_free_all(base64);
  return success;
}

size_t sxg_mi_sha256_size(size_t length, uint64_t record_size) {
  // See 2.1 of https://tools.ietf.org/html/draft-thomson-http-mice-03
  // Note:  This content encoding increases the size of a message by 8 plus
  // SHA256_DIGEST_LENGTH octets times the length of the message divided by the
  // record size, rounded up, less one.  That is, 8 + SHA256_DIGEST_LENGTH *
  // (ceil(length / rs) - 1).
  if (length == 0) {
    return 0u;
  } else {
    return sizeof(record_size) + length +
           SHA256_DIGEST_LENGTH *
               ((length + record_size - 1) / record_size - 1);
  }
}

size_t sxg_mi_sha256_remainder_size(size_t size, uint64_t record_size) {
  // If contents size == 0 chunk length must be 0.
  if (size == 0) {
    return 0;
  }
  // If no reminder exist, tail chunk length becomes record_size.
  if (size % record_size == 0) {
    return record_size;
  } else {
    return size % record_size;
  }
}

bool sxg_encode_mi_sha256(const uint8_t* src, size_t size, uint64_t record_size,
                          uint8_t* encoded,
                          uint8_t proof[SHA256_DIGEST_LENGTH]) {
  // See 2 of https://tools.ietf.org/html/draft-thomson-http-mice-03
  // proof(r[i]) = SHA-256(r[i] || proof(r[i+1]) || 0x1)
  // proof(r[last]) = SHA-256(r[last] || 0x0)
  // Result: rs || r[0] || proof(r[1]) || r[1] || proof(r[2]) || ... || r[last]
  // The integrity proof for the entire message is proof(r[0])
  // Note: The "||" operator is used to represent concatenation.
  if (record_size == 0) {
    return false;  // Avoid devision by zero.
  }

  // Construct encoded buffer from tail to head of source buffer.
  const uint8_t* input_p = src + size;
  uint8_t* output_p = encoded + sxg_mi_sha256_size(size, record_size);
  const size_t remainder = sxg_mi_sha256_remainder_size(size, record_size);

  uint8_t* workspace = OPENSSL_malloc(remainder + 1);
  if (workspace == NULL) {
    return false;
  }

  // The integrity proof for the final record is the hash of the record
  // with a single octet with a value 0x0 appended.
  workspace[remainder] = 0x0;
  if (remainder > 0) {
    input_p -= remainder;
    output_p -= remainder;
    memcpy(workspace, input_p, remainder);
    memcpy(output_p, input_p, remainder);
  }

  // Remainder buffer length can be devided by record_size.
  assert((input_p - src) % record_size == 0);

  if (!sxg_sha256(workspace, remainder + 1, proof)) {
    goto failure;
  }

  if (input_p == src) {
    // When one chunk contains whole buffer.
    OPENSSL_free(workspace);
    if (size != 0) {
      sxg_serialize_int(record_size, 8, encoded);
    }
    return true;
  }
  output_p -= SHA256_DIGEST_LENGTH;
  memcpy(output_p, proof, SHA256_DIGEST_LENGTH);

  const size_t workspace_size = record_size + SHA256_DIGEST_LENGTH + 1;
  workspace = OPENSSL_realloc(workspace, workspace_size);
  if (workspace == NULL) {
    goto failure;
  }

  memcpy(workspace + record_size, proof, SHA256_DIGEST_LENGTH);
  //  The integrity proof for all records other than the last is the hash of the
  //  concatenation of the record, the integrity proof of all subsequent
  //  records, and a single octet with a value of 0x1.
  workspace[SHA256_DIGEST_LENGTH + record_size] = 0x01;

  for (;;) {
    // Copy payload.
    output_p -= record_size;
    input_p -= record_size;
    memcpy(output_p, input_p, record_size);
    memcpy(workspace, input_p, record_size);

    // Calculate proof.
    if (!sxg_sha256(workspace, workspace_size, proof)) {
      goto failure;
    }
    if (input_p == src) {  // Reaches head of buffer
      break;
    }

    // Copy proof.
    output_p -= SHA256_DIGEST_LENGTH;
    memcpy(output_p, proof, SHA256_DIGEST_LENGTH);
    memcpy(workspace + record_size, proof,
           SHA256_DIGEST_LENGTH);  // Used for next proof.
  }
  OPENSSL_free(workspace);

  // Capacity for storing RecordSize must be remaining.
  assert(encoded + sizeof(record_size) == output_p);

  // Store RecordSize head 8 bytes of encoded data.
  sxg_serialize_int(record_size, 8, encoded);
  return true;

failure:
  OPENSSL_free(workspace);
  return false;
}

bool sxg_calculate_cert_sha256(X509* cert, uint8_t* dst) {
  const size_t length = i2d_X509(cert, NULL);
  uint8_t* cert_payload = OPENSSL_malloc(length);
  if (cert_payload == NULL) {
    return false;
  }

  // https://www.openssl.org/docs/man1.0.2/man3/d2i_X509_fp.html
  // WARNINGS: The use of temporary variable is mandatory.
  uint8_t* tmp_buf = cert_payload;
  const int encoded_bytes = i2d_X509(cert, &tmp_buf);
  if (encoded_bytes < 0) {
    OPENSSL_free(cert_payload);
    return false;
  }
  bool success = sxg_sha256(cert_payload, length, dst);

  assert((size_t)encoded_bytes == length);

  OPENSSL_free(cert_payload);
  return success;
}

static const EVP_MD* select_digest_function(EVP_PKEY* key) {
  const int keytype = EVP_PKEY_id(key);
  if (keytype == EVP_PKEY_EC) {
    const EC_KEY* const eckey = EVP_PKEY_get0_EC_KEY(key);
    switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey))) {
      case NID_X9_62_prime256v1:
      case NID_secp256k1:
        return EVP_sha256();
      case NID_secp384r1:
        return EVP_sha384();
      default:
        return NULL;
    }
  } else {
    return NULL;
  }
}

size_t sxg_evp_sign_size(EVP_PKEY* private_key, const uint8_t* src,
                         size_t length) {
  EVP_MD_CTX* const ctx = EVP_MD_CTX_create();
  const EVP_MD* digest_func = select_digest_function(private_key);
  size_t sig_size = 0;
  bool success =
      ctx != NULL &&
      (EVP_DigestSignInit(ctx, NULL, digest_func, NULL, private_key) == 1) &&
      (EVP_DigestSign(ctx, NULL, &sig_size, src, length) == 1);
  EVP_MD_CTX_destroy(ctx);
  if (!success) {
    return 0;
  }
  return sig_size;
}

size_t sxg_evp_sign(EVP_PKEY* private_key, const uint8_t* src, size_t length,
                    uint8_t* dst) {
  EVP_MD_CTX* const ctx = EVP_MD_CTX_create();
  const EVP_MD* digest_func = select_digest_function(private_key);
  // EVP_PKEY_sign_init() and EVP_PKEY_sign() return 1 for success and 0 or a
  // negative value for failure. In particular a return value of -2 indicates
  // the operation is not supported by the public key algorithm.
  size_t sig_size = 1024;
  bool success =
      ctx != NULL &&
      (EVP_DigestSignInit(ctx, NULL, digest_func, NULL, private_key) == 1) &&
      (EVP_DigestSign(ctx, dst, &sig_size, src, length) == 1);
  if (!success) {
    sig_size = 0;
  }
  EVP_MD_CTX_destroy(ctx);
  return sig_size;
}
