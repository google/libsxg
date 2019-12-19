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

#include "libsxg/sxg_buffer.h"

#include <assert.h>
#include <ctype.h>
#include <openssl/crypto.h>
#include <string.h>

#include "libsxg/internal/sxg_buffer.h"

// Ensures the buffer to have the capacity enough to receive additional
// desired_margin bytes. The content of the buffer will be preserved, but the
// pointer may be changed for memory reallocation.
//
// The capacity is default_capacity at minimum, and grows with doubling
// strategy. Extends buffer if it does not have enough space for
// desired_margin. For example, when the whole buffer already used and requires
// 1 more space, it will be expanded to twice capacity.
bool sxg_ensure_free_capacity_internal(size_t size, size_t desired_margin,
                                       size_t default_capacity,
                                       size_t item_size, size_t* capacity,
                                       void** buffer) {
  if (size + desired_margin <= *capacity) {
    return true;
  }

  size_t next_capacity = *capacity * 2;
  if (next_capacity < default_capacity) {
    next_capacity = default_capacity;
  }
  while (next_capacity < size + desired_margin) {
    next_capacity *= 2;
  }

  uint8_t* const new_buffer =
      OPENSSL_realloc(*buffer, next_capacity * item_size);
  if (new_buffer == NULL) {
    return false;
  }
  *buffer = new_buffer;
  *capacity = next_capacity;

  assert(size + desired_margin <= *capacity);

  return true;
}

static bool ensure_free_capacity(size_t desired_margin, sxg_buffer_t* target) {
  return sxg_ensure_free_capacity_internal(target->size, desired_margin, 1024,
                                           sizeof(uint8_t), &target->capacity,
                                           (void**)&target->data);
}

sxg_buffer_t sxg_empty_buffer() {
  static const sxg_buffer_t empty_buffer = {NULL, 0, 0};
  return empty_buffer;
}

bool sxg_buffer_resize(size_t size, sxg_buffer_t* target) {
  if (target->size < size &&
      !ensure_free_capacity(size - target->size, target)) {
    return false;
  }
  target->size = size;
  return true;
}

void sxg_buffer_release(sxg_buffer_t* target) {
  if (target->data != NULL) {
    OPENSSL_free(target->data);
  }
  *target = sxg_empty_buffer();
}

bool sxg_write_bytes(const uint8_t* bytes, size_t size, sxg_buffer_t* target) {
  if (size == 0) {
    return true;
  }
  if (!ensure_free_capacity(size, target)) {
    return false;
  }
  memcpy(target->data + target->size, bytes, size);
  target->size += size;
  return true;
}

bool sxg_write_buffer(const sxg_buffer_t* follower, sxg_buffer_t* target) {
  return sxg_write_bytes(follower->data, follower->size, target);
}

bool sxg_write_byte(uint8_t byte, sxg_buffer_t* target) {
  if (!ensure_free_capacity(1, target)) {
    return false;
  }
  target->data[target->size++] = byte;
  return true;
}

bool sxg_write_string(const char* string, sxg_buffer_t* target) {
  return sxg_write_bytes((const uint8_t*)string, strlen(string), target);
}

bool sxg_write_int(uint64_t num, int nbytes, sxg_buffer_t* target) {
  assert(1 <= nbytes && nbytes <= 8);

  if (!ensure_free_capacity(nbytes, target)) {
    return false;
  }
  for (int i = nbytes - 1; i >= 0; --i) {
    target->data[target->size++] = (num >> (8 * i)) & 0xff;
  }
  return true;
}

bool sxg_buffer_copy(const sxg_buffer_t* src, sxg_buffer_t* dst) {
  if (src->data == NULL || src->size == 0) {
    dst->size = 0;
    return true;
  }
  if (dst->size < src->size &&
      !ensure_free_capacity(src->size - dst->size, dst)) {
    return false;
  }
  memcpy(dst->data, src->data, src->size);
  dst->size = src->size;
  return true;
}
