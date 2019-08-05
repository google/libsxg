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

#include <ctype.h>
#include <stdio.h>

#include "libsxg/internal/sxg_buffer.h"
#include "libsxg/sxg_buffer.h"

void sxg_buffer_dump(const sxg_buffer_t* target) {
  if (target->size == 0) {
    printf("(empty data)\n");
    return;
  }
  for (size_t base = 0; base < target->size; base += 16) {
    printf("%06zx:", base);
    for (size_t col = 0; col < 16; ++col) {
      size_t i = base + col;
      if (col == 8) {
        putchar(' ');
      }
      if (i >= target->size) {
        printf("   ");
      } else {
        printf(" %02x", target->data[i]);
      }
    }
    printf("  |");
    for (int col = 0; col < 16; ++col) {
      size_t i = base + col;
      if (i >= target->size) {
        putchar(' ');
      } else {
        char c = target->data[i];
        putchar(isprint(c) ? c : '.');
      }
    }
    printf("|\n");
  }
}
