/*
 * Copyright (C) 2017 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <sysexits.h>

#include <android/hardware/boot/1.0/IBootControl.h>

#include <libavb_user/libavb_user.h>

using android::sp;
using android::hardware::hidl_string;
using android::hardware::Return;
using android::hardware::boot::V1_0::IBootControl;
using android::hardware::boot::V1_0::Slot;

namespace {

/* Prints program usage to |where|. */
void usage(FILE* where, int /* argc */, char* argv[]) {
  fprintf(where,
          "%s - command-line tool for AVB.\n"
          "\n"
          "Usage:\n"
          "  %s COMMAND\n"
          "\n"
          "Commands:\n"
          "  %s disable-verity    - Disable verity in current slot.\n"
          "  %s enable-verity     - Enable verity in current slot.\n",
          argv[0],
          argv[0],
          argv[0],
          argv[0]);
}

/* Returns the A/B suffix the device booted from or the empty string
 * if A/B is not in use.
 */
std::string get_ab_suffix(sp<IBootControl> module) {
  std::string suffix = "";

  if (module != nullptr) {
    uint32_t num_slots = module->getNumberSlots();
    if (num_slots > 1) {
      Slot cur_slot = module->getCurrentSlot();
      Return<void> ret =
          module->getSuffix(cur_slot, [&suffix](const hidl_string& value) {
            suffix = std::string(value.c_str());
          });
      if (!ret.isOk()) {
        fprintf(stderr, "Error getting suffix for slot %d.\n", cur_slot);
      }
    }
  }

  return suffix;
}

/* Loads the toplevel AvbVBMetaImageHeader from the slot denoted by
 * |ab_suffix| into |vbmeta_image|. No validation, verification, or
 * byteswapping is performed.
 *
 * If successful, |true| is returned and the partition it was loaded
 * from is returned in |out_partition_name| and the offset on said
 * partition is returned in |out_vbmeta_offset|.
 */
bool load_top_level_vbmeta_header(
    AvbOps* ops,
    const std::string& ab_suffix,
    uint8_t vbmeta_image[AVB_VBMETA_IMAGE_HEADER_SIZE],
    std::string* out_partition_name,
    uint64_t* out_vbmeta_offset) {
  std::string partition_name = std::string("vbmeta") + ab_suffix;
  uint64_t vbmeta_offset = 0;

  // Only read the header.
  size_t num_read;
  AvbIOResult io_res = ops->read_from_partition(ops,
                                                partition_name.c_str(),
                                                vbmeta_offset,
                                                AVB_VBMETA_IMAGE_HEADER_SIZE,
                                                vbmeta_image,
                                                &num_read);
  if (io_res == AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION) {
    AvbFooter footer;
    // Try looking for the vbmeta struct in 'boot' via the footer.
    partition_name = std::string("boot") + ab_suffix;
    io_res = ops->read_from_partition(ops,
                                      partition_name.c_str(),
                                      -AVB_FOOTER_SIZE,
                                      AVB_FOOTER_SIZE,
                                      &footer,
                                      &num_read);
    if (io_res != AVB_IO_RESULT_OK) {
      fprintf(stderr,
              "Error loading footer from partition '%s' (%d).\n",
              partition_name.c_str(),
              io_res);
      return false;
    }

    if (memcmp(footer.magic, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) != 0) {
      fprintf(stderr,
              "Data from '%s' does not look like a vbmeta footer.\n",
              partition_name.c_str());
      return false;
    }

    vbmeta_offset = avb_be64toh(footer.vbmeta_offset);
    io_res = ops->read_from_partition(ops,
                                      partition_name.c_str(),
                                      vbmeta_offset,
                                      AVB_VBMETA_IMAGE_HEADER_SIZE,
                                      vbmeta_image,
                                      &num_read);
  }

  if (io_res != AVB_IO_RESULT_OK) {
    fprintf(stderr,
            "Error loading from offset %" PRIu64 " of partition '%s' (%d).\n",
            vbmeta_offset,
            partition_name.c_str(),
            io_res);
    return false;
  }

  if (out_partition_name != nullptr) {
    *out_partition_name = partition_name;
  }
  if (out_vbmeta_offset != nullptr) {
    *out_vbmeta_offset = vbmeta_offset;
  }
  return true;
}

/* Function to enable and disable dm-verity. The |ops| parameter
 * should be an |AvbOps| from libavb_user and |module| can either be
 * |nullptr| or a valid boot_control module.
 */
int do_set_verity(AvbOps* ops, sp<IBootControl> module, bool enable_verity) {
  uint8_t vbmeta_image[AVB_VBMETA_IMAGE_HEADER_SIZE];  // 256 bytes.
  std::string ab_suffix;
  std::string partition_name;
  uint64_t vbmeta_offset;
  AvbIOResult io_res;

  ab_suffix = get_ab_suffix(module);

  if (!load_top_level_vbmeta_header(
          ops, ab_suffix, vbmeta_image, &partition_name, &vbmeta_offset)) {
    return EX_SOFTWARE;
  }

  if (memcmp(vbmeta_image, AVB_MAGIC, AVB_MAGIC_LEN) != 0) {
    fprintf(stderr,
            "Data from '%s' does not look like a vbmeta header.\n",
            partition_name.c_str());
    return EX_SOFTWARE;
  }

  // Set/clear the HASHTREE_DISABLED bit, as requested.
  AvbVBMetaImageHeader* header =
      reinterpret_cast<AvbVBMetaImageHeader*>(vbmeta_image);
  uint32_t flags = avb_be32toh(header->flags);
  flags &= ~AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED;
  if (!enable_verity) {
    flags |= AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED;
  }
  header->flags = avb_htobe32(flags);

  // Write the header.
  io_res = ops->write_to_partition(ops,
                                   partition_name.c_str(),
                                   vbmeta_offset,
                                   AVB_VBMETA_IMAGE_HEADER_SIZE,
                                   vbmeta_image);
  if (io_res != AVB_IO_RESULT_OK) {
    fprintf(stderr,
            "Error writing to offset %" PRIu64 " of partition '%s' (%d).\n",
            vbmeta_offset,
            partition_name.c_str(),
            io_res);
    return EX_SOFTWARE;
  }

  fprintf(stdout,
          "Successfully %s verity on %s.\n",
          enable_verity ? "enabled" : "disabled",
          partition_name.c_str());

  return EX_OK;
}

}  // namespace

int main(int argc, char* argv[]) {
  int ret;
  sp<IBootControl> module;
  AvbOps* ops = nullptr;

  if (argc < 2) {
    usage(stderr, argc, argv);
    ret = EX_USAGE;
    goto out;
  }

  ops = avb_ops_user_new();
  if (ops == nullptr) {
    fprintf(stderr, "Error getting AVB ops.\n");
    ret = EX_SOFTWARE;
    goto out;
  }

  // Failing to get the boot_control HAL is not a fatal error - it can
  // happen if A/B is not in use, in which case |nullptr| is returned.
  module = IBootControl::getService();

  if (strcmp(argv[1], "disable-verity") == 0) {
    ret = do_set_verity(ops, module, false);
  } else if (strcmp(argv[1], "enable-verity") == 0) {
    ret = do_set_verity(ops, module, true);
  } else {
    usage(stderr, argc, argv);
    ret = EX_USAGE;
  }

  ret = EX_OK;
out:
  if (ops != nullptr) {
    avb_ops_user_free(ops);
  }
  return ret;
}
