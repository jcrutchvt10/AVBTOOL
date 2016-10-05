/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <endian.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "avb_sysdeps.h"

int avb_memcmp(const void* src1, const void* src2, size_t n) {
  return memcmp(src1, src2, n);
}

void* avb_memcpy(void* dest, const void* src, size_t n) {
  return memcpy(dest, src, n);
}

void* avb_memset(void* dest, const int c, size_t n) {
  return memset(dest, c, n);
}

int avb_strcmp(const char* s1, const char* s2) { return strcmp(s1, s2); }

size_t avb_strlen(const char* str) { return strlen(str); }

void avb_abort(void) { abort(); }

void avb_print(const char* message) { fprintf(stderr, "%s", message); }

void avb_printv(const char* message, ...) {
  va_list ap;
  const char* m;

  va_start(ap, message);
  for (m = message; m != NULL; m = va_arg(ap, const char*)) {
    fprintf(stderr, "%s", m);
  }
  va_end(ap);
}

void* avb_malloc_(size_t size) { return malloc(size); }

void avb_free(void* ptr) { free(ptr); }
