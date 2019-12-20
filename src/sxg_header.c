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

#include "libsxg/sxg_header.h"

#include <assert.h>
#include <ctype.h>
#include <inttypes.h>
#include <openssl/crypto.h>
#include <stdio.h>
#include <string.h>

#include "libsxg/internal/sxg_buffer.h"
#include "libsxg/internal/sxg_cbor.h"

sxg_header_t sxg_empty_header() {
  const sxg_header_t structure = {NULL, 0, 0};
  return structure;
}

void sxg_header_release(sxg_header_t* target) {
  for (size_t i = 0; i < target->size; ++i) {
    OPENSSL_free(target->entries[i].key);
    sxg_buffer_release(&target->entries[i].value);
  }
  if (target->entries != NULL) {
    OPENSSL_free(target->entries);
  }
  *target = sxg_empty_header();
}

static bool ensure_free_capacity(size_t desired_margin, sxg_header_t* target) {
  return sxg_ensure_free_capacity_internal(target->size, desired_margin, 8,
                                           sizeof(sxg_kvp_t), &target->capacity,
                                           (void**)&target->entries);
}

static bool case_insensitive_strcmp(const char* a, const char* b) {
  for (size_t i = 0;; i++) {
    const int left = tolower(a[i]);
    const int right = tolower(b[i]);
    if (left == 0 && right == 0) {
      return true;
    }
    if (left != right) {
      return false;
    }
  }
}

static sxg_buffer_t* get_or_create_buffer(const char* key,
                                          sxg_header_t* target) {
  // Entries are expected to have small number of entries because they are HTTP
  // header, so linear search is not a bad solution.
  const size_t length = strlen(key);
  for (size_t i = 0; i < target->size; ++i) {
    if (case_insensitive_strcmp(target->entries[i].key, key)) {
      if (!sxg_write_byte(',', &target->entries[i].value)) {
        return NULL;
      }
      return &target->entries[i].value;
    }
  }

  // When existing key is not found, create new entry in lowercase.
  if (!ensure_free_capacity(1, target)) {
    return NULL;
  }
  char* const copied_key = OPENSSL_strdup(key);
  if (copied_key == NULL) {
    return NULL;
  }
  for (size_t i = 0; i < length; ++i) {
    copied_key[i] = tolower(copied_key[i]);
  }
  target->entries[target->size].key = copied_key;
  target->entries[target->size].value = sxg_empty_buffer();
  return &target->entries[target->size++].value;
}

bool sxg_header_append_string(const char* key, const char* value,
                              sxg_header_t* target) {
  sxg_buffer_t* const buf = get_or_create_buffer(key, target);
  return buf != NULL && sxg_write_string(value, buf);
}

bool sxg_header_append_buffer(const char* key, const sxg_buffer_t* value,
                              sxg_header_t* target) {
  sxg_buffer_t* const buf = get_or_create_buffer(key, target);
  return buf != NULL && sxg_write_buffer(value, buf);
}

bool sxg_header_append_integer(const char* key, uint64_t num,
                               sxg_header_t* target) {
  char integer_buffer[21];  // len(str(2 ** 64 - 1)) = 20
  snprintf(integer_buffer, sizeof(integer_buffer), "%" PRIu64, num);

  sxg_buffer_t* buf = get_or_create_buffer(key, target);
  return buf != NULL && sxg_write_string(integer_buffer, buf);
}

bool sxg_header_copy(const sxg_header_t* src, sxg_header_t* dst) {
  if (src->size == 0) {
    sxg_header_release(dst);
    return true;
  }
  sxg_header_t tmp = sxg_empty_header();
  if (!ensure_free_capacity(src->size, &tmp)) {
    return false;
  }
  for (size_t i = 0; i < src->size; ++i) {
    sxg_kvp_t* const new_entry = &tmp.entries[tmp.size++];
    new_entry->key = OPENSSL_strdup(src->entries[i].key);
    new_entry->value = sxg_empty_buffer();
    if (new_entry->key == NULL ||
        !sxg_buffer_copy(&src->entries[i].value, &new_entry->value)) {
      sxg_header_release(&tmp);
      return false;
    }
  }
  sxg_header_release(dst);
  *dst = tmp;
  return true;
}

bool sxg_header_merge(const sxg_header_t* src, sxg_header_t* target) {
  bool success = true;
  for (size_t i = 0; i < src->size && success; ++i) {
    success =
        success && sxg_header_append_buffer(src->entries[i].key,
                                            &src->entries[i].value, target);
  }
  return success;
}

// Only used for qsort().
// Reorders header structure to canonical CBOR serialization order.
// https://tools.ietf.org/html/draft-yasskin-http-origin-signed-responses-05#section-3.4
// The keys in every map MUST be sorted in the bytewise lexicographic order of
// their canonical *encodings*. CBOR encoding adds the size as prefix so that
// shorter keys must come first, before lexicographical order.
// Sorting keys *before* encoding avoids extra memory allocation and copy cost.
static int header_encoding_order(const void* a, const void* b) {
  const sxg_kvp_t* const l = a;
  const sxg_kvp_t* const r = b;
  const size_t lsize = strlen(l->key);
  const size_t rsize = strlen(r->key);
  if (lsize < rsize) {
    return -1;
  } else if (lsize > rsize) {
    return 1;
  } else {
    return strcmp(l->key, r->key);
  }
}

bool sxg_header_serialize_cbor(const sxg_header_t* src, sxg_buffer_t* dst) {
  const size_t size = src->size;

  // Make a copy of entries map to sort.
  sxg_buffer_t tmp_entries_buffer = sxg_empty_buffer();
  if (!sxg_buffer_resize(src->size * sizeof(sxg_kvp_t), &tmp_entries_buffer)) {
    return false;
  }
  sxg_kvp_t* entries = (sxg_kvp_t*)tmp_entries_buffer.data;

  if (src->size > 0) {
    memcpy(entries, src->entries, src->size * sizeof(sxg_kvp_t));
    qsort(entries, size, sizeof(sxg_kvp_t), header_encoding_order);
  }

  bool success = sxg_write_map_cbor_header(size, dst);
  for (size_t i = 0; i < size && success; ++i) {
    success = success && sxg_write_bytes_cbor((const uint8_t*)entries[i].key,
                                              strlen(entries[i].key), dst);
    success = success && sxg_write_bytes_cbor(entries[i].value.data,
                                              entries[i].value.size, dst);
  }

  sxg_buffer_release(&tmp_entries_buffer);
  return success;
}
