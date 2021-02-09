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
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <string.h>

static bool sxg_calc_sha256_bytes(const sxg_buffer_t* src,
                                  uint8_t out[SHA256_DIGEST_LENGTH]) {
  return SHA256(src->data, src->size, out) != NULL;
}

bool sxg_calc_sha256(const sxg_buffer_t* src, sxg_buffer_t* dst) {
  sxg_buffer_release(dst);
  return sxg_buffer_resize(SHA256_DIGEST_LENGTH, dst) &&
         sxg_calc_sha256_bytes(src, dst->data);
}

bool sxg_calc_sha384(const sxg_buffer_t* src, sxg_buffer_t* dst) {
  sxg_buffer_release(dst);
  return sxg_buffer_resize(SHA384_DIGEST_LENGTH, dst) &&
         SHA384(src->data, src->size, dst->data);
}

bool sxg_base64encode_bytes(const uint8_t* src, size_t length,
                            sxg_buffer_t* dst) {
  const size_t offset = dst->size;
  // 3-byte blocks to 4-byte, rounded up
  const EVP_ENCODE_BLOCK_T out_length = 4 * ((length + 2) / 3);
  if (out_length < 0 || (size_t)out_length < length) return false;

  return sxg_buffer_resize(offset + out_length, dst) &&
         EVP_EncodeBlock(dst->data + offset, src, length) == out_length;
}

bool sxg_base64encode(const sxg_buffer_t* src, sxg_buffer_t* dst) {
  return sxg_base64encode_bytes(src->data, src->size, dst);
}

static void encode_uint64_to_buffer(uint64_t num, uint8_t buf[8]) {
  for (int i = 0; i < 8; ++i) {
    buf[i] = (num >> 8 * (7 - i)) & 0xffu;
  }
}

static size_t mi_sha256_encoded_size(size_t length, uint64_t record_size) {
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

static size_t mi_sha256_remainder_size(size_t size, uint64_t record_size) {
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

bool sxg_encode_mi_sha256(const sxg_buffer_t* src, uint64_t record_size,
                          sxg_buffer_t* encoded,
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

  const size_t encoded_size = mi_sha256_encoded_size(src->size, record_size);
  if (!sxg_buffer_resize(encoded_size, encoded)) {
    return false;
  }
  encoded->size = encoded_size;

  // Construct encoded buffer from tail to head of source buffer.
  const uint8_t* input_p = src->data + src->size;
  uint8_t* output_p = encoded->data + encoded_size;
  const size_t remainder = mi_sha256_remainder_size(src->size, record_size);

  sxg_buffer_t workspace = sxg_empty_buffer();
  if (!sxg_buffer_resize(remainder + 1, &workspace)) {
    sxg_buffer_release(encoded);
    return false;
  }

  // The integrity proof for the final record is the hash of the record
  // with a single octet with a value 0x0 appended.
  workspace.data[remainder] = 0x0;
  if (remainder > 0) {
    input_p -= remainder;
    output_p -= remainder;
    memcpy(workspace.data, input_p, remainder);
    memcpy(output_p, input_p, remainder);
  }

  // Remainder buffer length can be devided by record_size.
  assert((input_p - src->data) % record_size == 0);

  if (!sxg_calc_sha256_bytes(&workspace, proof)) {
    goto failure;
  }

  if (input_p == src->data) {
    // When one chunk contains whole buffer.
    sxg_buffer_release(&workspace);
    if (src->size != 0) {
      encode_uint64_to_buffer(record_size, encoded->data);
    }
    return true;
  }
  output_p -= SHA256_DIGEST_LENGTH;
  memcpy(output_p, proof, SHA256_DIGEST_LENGTH);

  if (!sxg_buffer_resize(record_size + SHA256_DIGEST_LENGTH + 1, &workspace)) {
    goto failure;
  }

  memcpy(workspace.data + record_size, proof, SHA256_DIGEST_LENGTH);
  //  The integrity proof for all records other than the last is the hash of the
  //  concatenation of the record, the integrity proof of all subsequent
  //  records, and a single octet with a value of 0x1.
  workspace.data[SHA256_DIGEST_LENGTH + record_size] = 0x01;

  for (;;) {
    // Copy payload.
    output_p -= record_size;
    input_p -= record_size;
    memcpy(output_p, input_p, record_size);
    memcpy(workspace.data, input_p, record_size);

    // Calculate proof.
    if (!sxg_calc_sha256_bytes(&workspace, proof)) {
      goto failure;
    }
    if (input_p == src->data) {  // Reaches head of buffer
      break;
    }

    // Copy proof.
    output_p -= SHA256_DIGEST_LENGTH;
    memcpy(output_p, proof, SHA256_DIGEST_LENGTH);
    memcpy(workspace.data + record_size, proof,
           SHA256_DIGEST_LENGTH);  // Used for next proof.
  }
  sxg_buffer_release(&workspace);

  // Capacity for storing RecordSize must be remaining.
  assert(encoded->data + sizeof(record_size) == output_p);

  // Store RecordSize head 8 bytes of encoded data.
  encode_uint64_to_buffer(record_size, encoded->data);
  return true;

failure:
  sxg_buffer_release(&workspace);
  sxg_buffer_release(encoded);
  return false;
}

bool sxg_calculate_cert_sha256(X509* cert, sxg_buffer_t* dst) {
  sxg_buffer_t cert_payload = sxg_empty_buffer();
  const size_t length = i2d_X509(cert, NULL);
  if (!sxg_buffer_resize(length, &cert_payload)) {
    return false;
  }

  // https://www.openssl.org/docs/man1.0.2/man3/d2i_X509_fp.html
  // WARNINGS: The use of temporary variable is mandatory.
  unsigned char* tmp_buf = cert_payload.data;
  const int encoded_bytes = i2d_X509(cert, &tmp_buf);
  if (encoded_bytes < 0) {
    sxg_buffer_release(&cert_payload);
    return false;
  }
  bool success = sxg_calc_sha256(&cert_payload, dst);

  assert((size_t)encoded_bytes == length);

  sxg_buffer_release(&cert_payload);
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

bool sxg_evp_sign(EVP_PKEY* private_key, const sxg_buffer_t* src,
                  sxg_buffer_t* dst) {
  EVP_MD_CTX* const ctx = EVP_MD_CTX_new();
  const EVP_MD* digest_func = select_digest_function(private_key);

  // EVP_PKEY_sign_init() and EVP_PKEY_sign() return 1 for success and 0 or a
  // negative value for failure. In particular a return value of -2 indicates
  // the operation is not supported by the public key algorithm.
  size_t sig_size = 0;
  bool success =
      ctx != NULL &&
      (EVP_DigestSignInit(ctx, NULL, digest_func, NULL, private_key) == 1) &&
      (EVP_DigestSign(ctx, NULL, &sig_size, src->data, src->size) == 1) &&
      sxg_buffer_resize(sig_size, dst) &&
      (EVP_DigestSign(ctx, dst->data, &dst->size, src->data, src->size) == 1);

  EVP_MD_CTX_free(ctx);
  return success;
}
