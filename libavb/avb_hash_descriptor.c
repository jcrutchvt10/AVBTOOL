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

#include "avb_hash_descriptor.h"
#include "avb_util.h"

bool avb_hash_descriptor_validate_and_byteswap(const AvbHashDescriptor* src,
                                               AvbHashDescriptor* dest) {
  uint64_t expected_size;

  avb_memcpy(dest, src, sizeof(AvbHashDescriptor));

  if (!avb_descriptor_validate_and_byteswap((const AvbDescriptor*)src,
                                            (AvbDescriptor*)dest))
    return false;

  if (dest->parent_descriptor.tag != AVB_DESCRIPTOR_TAG_HASH) {
    avb_error("Invalid tag for hash descriptor.\n");
    return false;
  }

  dest->image_size = avb_be64toh(dest->image_size);
  dest->partition_name_len = avb_be32toh(dest->partition_name_len);
  dest->salt_len = avb_be32toh(dest->salt_len);
  dest->digest_len = avb_be32toh(dest->digest_len);

  /* Check that partition_name, salt, and digest are fully contained. */
  expected_size = sizeof(AvbHashDescriptor) - sizeof(AvbDescriptor);
  if (!avb_safe_add_to(&expected_size, dest->partition_name_len) ||
      !avb_safe_add_to(&expected_size, dest->salt_len) ||
      !avb_safe_add_to(&expected_size, dest->digest_len)) {
    avb_error("Overflow while adding up sizes.\n");
    return false;
  }
  if (expected_size > dest->parent_descriptor.num_bytes_following) {
    avb_error("Descriptor payload size overflow.\n");
    return false;
  }
  return true;
}
