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

#include "libsxg/internal/sxg_cbor.h"

#include <string.h>

#include "libsxg/internal/sxg_buffer.h"

size_t sxg_write_initial_bytes_size(uint64_t length) {
  // https://tools.ietf.org/html/rfc7049#appendix-B
  // It writes cbor header for the type.
  // In SXG, using smallest type header as possible is required.
  if (length <= 0x17) {
    return 1;
  } else if (length <= 0xff) {
    return 2;
  } else if (length <= 0xffff) {
    return 3;
  } else if (length <= 0xffffffffULL) {
    return 5;
  } else {
    return 9;
  }
}

void sxg_write_initial_bytes(uint8_t type_offset, uint64_t length,
                             uint8_t* target) {
  // https://tools.ietf.org/html/rfc7049#appendix-B
  // It writes cbor header for the type.
  // In SXG, using smallest type header as possible is required.
  if (length <= 0x17) {
    target[0] = type_offset + length;
  } else if (length <= 0xff) {
    target[0] = type_offset + 0x18;
    sxg_serialize_int(length, 1, &target[1]);
  } else if (length <= 0xffff) {
    target[0] = type_offset + 0x19;
    sxg_serialize_int(length, 2, &target[1]);
  } else if (length <= 0xffffffffULL) {
    target[0] = type_offset + 0x1a;
    sxg_serialize_int(length, 4, &target[1]);
  } else {
    target[0] = type_offset + 0x1b;
    sxg_serialize_int(length, 8, &target[1]);
  }
}

static bool write_cbor_header(uint8_t type_offset, uint64_t length,
                              sxg_buffer_t* target) {
  size_t tail = target->size;
  if (!sxg_buffer_resize(target->size + sxg_write_initial_bytes_size(length),
                         target)) {
    return false;
  }
  sxg_write_initial_bytes(type_offset, length, &target->data[tail]);
  return true;
}

bool sxg_write_bytes_cbor_header(uint64_t length, sxg_buffer_t* target) {
  return write_cbor_header(0x40, length, target);
}

bool sxg_write_utf8_cbor_header(uint64_t length, sxg_buffer_t* target) {
  return write_cbor_header(0x60, length, target);
}

bool sxg_write_map_cbor_header(uint64_t size, sxg_buffer_t* target) {
  return write_cbor_header(0xa0, size, target);
}

bool sxg_write_array_cbor_header(uint64_t length, sxg_buffer_t* target) {
  return write_cbor_header(0x80, length, target);
}

bool sxg_write_utf8string_cbor(const char* string, sxg_buffer_t* target) {
  size_t length = strlen(string);
  return sxg_write_utf8_cbor_header(length, target) &&
         sxg_write_bytes((const uint8_t*)string, length, target);
}

bool sxg_write_bytes_cbor(const uint8_t* bytes, size_t length,
                          sxg_buffer_t* target) {
  return sxg_write_bytes_cbor_header(length, target) &&
         sxg_write_bytes(bytes, length, target);
}
