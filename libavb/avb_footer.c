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

#include "avb_footer.h"
#include "avb_util.h"

bool avb_footer_validate_and_byteswap(const AvbFooter* src, AvbFooter* dest) {
  avb_memcpy(dest, src, sizeof(AvbFooter));

  dest->version_major = avb_be32toh(dest->version_major);
  dest->version_minor = avb_be32toh(dest->version_minor);

  dest->original_image_size = avb_be64toh(dest->original_image_size);
  dest->vbmeta_offset = avb_be64toh(dest->vbmeta_offset);
  dest->vbmeta_size = avb_be64toh(dest->vbmeta_size);

  /* Check that magic is correct. */
  if (avb_safe_memcmp(dest->magic, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) !=
      0) {
    avb_error("Footer magic is incorrect.\n");
    return false;
  }

  /* Ensure we don't attempt to access any fields if the footer major
   * version is not supported.
   */
  if (dest->version_major > AVB_FOOTER_MAJOR_VERSION) {
    avb_error("No support for footer version.\n");
    return false;
  }

  return true;
}
