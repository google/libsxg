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

static bool write_initial_bytes(uint8_t type_offset, uint64_t length,
                                sxg_buffer_t* target) {
  // https://tools.ietf.org/html/rfc7049#appendix-B
  // It writes cbor header for the type.
  // In SXG, using smallest type header as possible is required.
  if (length <= 0x17) {
    return sxg_write_byte(type_offset + length, target);
  } else if (length <= 0xff) {
    return sxg_write_byte(type_offset + 0x18, target) &&
           sxg_write_int(length, 1, target);
  } else if (length <= 0xffff) {
    return sxg_write_byte(type_offset + 0x19, target) &&
           sxg_write_int(length, 2, target);
  } else if (length <= 0xffffffffULL) {
    return sxg_write_byte(type_offset + 0x1a, target) &&
           sxg_write_int(length, 4, target);
  } else {
    return sxg_write_byte(type_offset + 0x1b, target) &&
           sxg_write_int(length, 8, target);
  }
}

bool sxg_write_bytes_cbor_header(uint64_t length, sxg_buffer_t* target) {
  return write_initial_bytes(0x40, length, target);
}

bool sxg_write_utf8_cbor_header(uint64_t length, sxg_buffer_t* target) {
  return write_initial_bytes(0x60, length, target);
}

bool sxg_write_map_cbor_header(uint64_t size, sxg_buffer_t* target) {
  return write_initial_bytes(0xa0, size, target);
}

bool sxg_write_array_cbor_header(uint64_t length, sxg_buffer_t* target) {
  return write_initial_bytes(0x80, length, target);
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
