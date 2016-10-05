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

#include <iostream>

#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <base/files/file_util.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "avb_unittest_util.h"
#include "libavb.h"

struct MyAvbOps;
typedef struct MyAvbOps MyAvbOps;

class MyOps {
 public:
  MyOps();
  ~MyOps();

  AvbOps* avb_ops() { return (AvbOps*)avb_ops_; }

  void set_partition_dir(const base::FilePath& partition_dir) {
    partition_dir_ = partition_dir;
  }

  void set_expected_public_key(const std::string& expected_public_key) {
    expected_public_key_ = expected_public_key;
  }

  void set_stored_rollback_indexes(
      const std::vector<uint64_t>& stored_rollback_indexes) {
    stored_rollback_indexes_ = stored_rollback_indexes;
  }

  void set_stored_is_device_unlocked(bool stored_is_device_unlocked) {
    stored_is_device_unlocked_ = stored_is_device_unlocked;
  }

  AvbIOResult read_from_partition(const char* partition, int64_t offset,
                                  size_t num_bytes, void* buffer,
                                  size_t* out_num_read) {
    base::FilePath path =
        partition_dir_.Append(std::string(partition)).AddExtension("img");

    if (offset < 0) {
      int64_t file_size;
      if (!base::GetFileSize(path, &file_size)) {
        fprintf(stderr, "Error getting size of file '%s'\n",
                path.value().c_str());
        return AVB_IO_RESULT_ERROR_IO;
      }
      offset = file_size - (-offset);
    }

    int fd = open(path.value().c_str(), O_RDONLY);
    if (fd < 0) {
      fprintf(stderr, "Error opening file '%s': %s\n", path.value().c_str(),
              strerror(errno));
      return AVB_IO_RESULT_ERROR_IO;
    }
    if (lseek(fd, offset, SEEK_SET) != offset) {
      fprintf(stderr, "Error seeking to pos %zd in file %s: %s\n", offset,
              path.value().c_str(), strerror(errno));
      close(fd);
      return AVB_IO_RESULT_ERROR_IO;
    }
    ssize_t num_read = read(fd, buffer, num_bytes);
    if (num_read < 0) {
      fprintf(stderr,
              "Error reading %zd bytes from pos %" PRId64 " in file %s: %s\n",
              num_bytes, offset, path.value().c_str(), strerror(errno));
      close(fd);
      return AVB_IO_RESULT_ERROR_IO;
    }
    close(fd);

    if (out_num_read != NULL) {
      *out_num_read = num_read;
    }

    return AVB_IO_RESULT_OK;
  }

  AvbIOResult write_to_partition(const char* partition, int64_t offset,
                                 size_t num_bytes, const void* buffer) {
    base::FilePath path =
        partition_dir_.Append(std::string(partition)).AddExtension("img");

    if (offset < 0) {
      int64_t file_size;
      if (!base::GetFileSize(path, &file_size)) {
        fprintf(stderr, "Error getting size of file '%s'\n",
                path.value().c_str());
        return AVB_IO_RESULT_ERROR_IO;
      }
      offset = file_size - (-offset);
    }

    int fd = open(path.value().c_str(), O_WRONLY);
    if (fd < 0) {
      fprintf(stderr, "Error opening file '%s': %s\n", path.value().c_str(),
              strerror(errno));
      return AVB_IO_RESULT_ERROR_IO;
    }
    if (lseek(fd, offset, SEEK_SET) != offset) {
      fprintf(stderr, "Error seeking to pos %zd in file %s: %s\n", offset,
              path.value().c_str(), strerror(errno));
      close(fd);
      return AVB_IO_RESULT_ERROR_IO;
    }
    ssize_t num_written = write(fd, buffer, num_bytes);
    if (num_written < 0) {
      fprintf(stderr,
              "Error writing %zd bytes at pos %" PRId64 " in file %s: %s\n",
              num_bytes, offset, path.value().c_str(), strerror(errno));
      close(fd);
      return AVB_IO_RESULT_ERROR_IO;
    }
    close(fd);

    return AVB_IO_RESULT_OK;
  }

  int validate_vbmeta_public_key(AvbOps* ops, const uint8_t* public_key_data,
                                 size_t public_key_length) {
    if (public_key_length != expected_public_key_.size()) return 0;

    return memcmp(expected_public_key_.c_str(), public_key_data,
                  public_key_length) == 0;
  }

  bool read_rollback_index(AvbOps* ops, size_t rollback_index_slot,
                           uint64_t* out_rollback_index) {
    if (rollback_index_slot >= stored_rollback_indexes_.size()) {
      fprintf(stderr, "No rollback index for slot %zd (has %zd slots).\n",
              rollback_index_slot, stored_rollback_indexes_.size());
      return false;
    }
    *out_rollback_index = stored_rollback_indexes_[rollback_index_slot];
    return true;
  }

  bool write_rollback_index(AvbOps* ops, size_t rollback_index_slot,
                            uint64_t rollback_index) {
    fprintf(stderr, "write_rollback_index not yet implemented.\n");
    return false;
  }

  bool read_is_device_unlocked(AvbOps* ops, bool* out_is_device_unlocked) {
    *out_is_device_unlocked = stored_is_device_unlocked_ ? 1 : 0;
    return true;
  }

  bool get_unique_guid_for_partition(AvbOps* ops, const char* partition,
                                     char* guid_buf, size_t guid_buf_size) {
    // This is faking it a bit but makes testing easy. It works
    // because avb_slot_verify.c doesn't check that the returned GUID
    // is wellformed.
    snprintf(guid_buf, guid_buf_size, "1234-fake-guid-for:%s", partition);
    return true;
  }

  MyAvbOps* avb_ops_;

  base::FilePath partition_dir_;

  std::string expected_public_key_;

  std::vector<uint64_t> stored_rollback_indexes_;

  bool stored_is_device_unlocked_;
};

struct MyAvbOps {
  AvbOps parent;
  MyOps* my_ops;
};

static AvbIOResult my_ops_read_from_partition(AvbOps* ops,
                                              const char* partition,
                                              int64_t offset, size_t num_bytes,
                                              void* buffer,
                                              size_t* out_num_read) {
  return ((MyAvbOps*)ops)
      ->my_ops->read_from_partition(partition, offset, num_bytes, buffer,
                                    out_num_read);
}

static AvbIOResult my_ops_write_to_partition(AvbOps* ops, const char* partition,
                                             int64_t offset, size_t num_bytes,
                                             const void* buffer) {
  return ((MyAvbOps*)ops)
      ->my_ops->write_to_partition(partition, offset, num_bytes, buffer);
}

static bool my_ops_validate_vbmeta_public_key(AvbOps* ops,
                                              const uint8_t* public_key_data,
                                              size_t public_key_length) {
  return ((MyAvbOps*)ops)
      ->my_ops->validate_vbmeta_public_key(ops, public_key_data,
                                           public_key_length);
}

static bool my_ops_read_rollback_index(AvbOps* ops, size_t rollback_index_slot,
                                       uint64_t* out_rollback_index) {
  return ((MyAvbOps*)ops)
      ->my_ops->read_rollback_index(ops, rollback_index_slot,
                                    out_rollback_index);
}

static bool my_ops_write_rollback_index(AvbOps* ops, size_t rollback_index_slot,
                                        uint64_t rollback_index) {
  return ((MyAvbOps*)ops)
      ->my_ops->write_rollback_index(ops, rollback_index_slot, rollback_index);
}

static bool my_ops_read_is_device_unlocked(AvbOps* ops,
                                           bool* out_is_device_unlocked) {
  return ((MyAvbOps*)ops)
      ->my_ops->read_is_device_unlocked(ops, out_is_device_unlocked);
}

static bool my_ops_get_unique_guid_for_partition(AvbOps* ops,
                                                 const char* partition,
                                                 char* guid_buf,
                                                 size_t guid_buf_size) {
  return ((MyAvbOps*)ops)
      ->my_ops->get_unique_guid_for_partition(ops, partition, guid_buf,
                                              guid_buf_size);
}

MyOps::MyOps() {
  avb_ops_ = new MyAvbOps;
  avb_ops_->parent.read_from_partition = my_ops_read_from_partition;
  avb_ops_->parent.write_to_partition = my_ops_write_to_partition;
  avb_ops_->parent.validate_vbmeta_public_key =
      my_ops_validate_vbmeta_public_key;
  avb_ops_->parent.read_rollback_index = my_ops_read_rollback_index;
  avb_ops_->parent.write_rollback_index = my_ops_write_rollback_index;
  avb_ops_->parent.read_is_device_unlocked = my_ops_read_is_device_unlocked;
  avb_ops_->parent.get_unique_guid_for_partition =
      my_ops_get_unique_guid_for_partition;
  avb_ops_->my_ops = this;
}

MyOps::~MyOps() { delete avb_ops_; }

class AvbSlotVerifyTest : public BaseAvbToolTest {
 public:
  AvbSlotVerifyTest() {}

  virtual void SetUp() override {
    BaseAvbToolTest::SetUp();
    ops_.set_partition_dir(testdir_);
    ops_.set_stored_rollback_indexes({0, 0, 0, 0});
    ops_.set_stored_is_device_unlocked(false);
  }

  base::FilePath GenerateImage(const std::string file_name, size_t image_size) {
    // Generate a 1025 KiB file with known content.
    std::vector<uint8_t> image;
    image.resize(image_size);
    for (size_t n = 0; n < image_size; n++) {
      image[n] = uint8_t(n);
    }
    base::FilePath image_path = testdir_.Append(file_name);
    EXPECT_EQ(image_size,
              static_cast<const size_t>(base::WriteFile(
                  image_path, reinterpret_cast<const char*>(image.data()),
                  image.size())));
    return image_path;
  }

  MyOps ops_;
};

TEST_F(AvbSlotVerifyTest, Basic) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), "_a", &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "androidboot.slot_suffix=_a androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1408 "
      "androidboot.vbmeta.digest=22cda7342f5ba915f41662975f96f081",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, BasicSha512) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA512_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), "_a", &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "androidboot.slot_suffix=_a androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha512 androidboot.vbmeta.size=1472 "
      "androidboot.vbmeta.digest="
      "125592a19a266efe6683de1afee53e2585ccfcf33adb5d6485e6fbfeabccf571",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, BasicUnlocked) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  ops_.set_stored_is_device_unlocked(true);

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), "_a", &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "androidboot.slot_suffix=_a androidboot.vbmeta.device_state=unlocked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1408 "
      "androidboot.vbmeta.digest=22cda7342f5ba915f41662975f96f081",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, SlotDataIsCorrect) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));
}

TEST_F(AvbSlotVerifyTest, WrongPublicKey) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));
}

TEST_F(AvbSlotVerifyTest, NoImage) {
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_IO,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));
}

TEST_F(AvbSlotVerifyTest, UnsignedVBMeta) {
  GenerateVBMetaImage("vbmeta_a.img", "", 0, base::FilePath(""));

  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));
}

TEST_F(AvbSlotVerifyTest, CorruptedImage) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  // Corrupt four bytes of data in the end of the image. Since the aux
  // data is at the end and this data is signed, this will change the
  // value of the computed hash.
  uint8_t corrupt_data[4] = {0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(AVB_IO_RESULT_OK, ops_.avb_ops()->write_to_partition(
                                  ops_.avb_ops(), "vbmeta_a",
                                  -sizeof corrupt_data,  // offset from end
                                  sizeof corrupt_data, corrupt_data));

  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));
}

TEST_F(AvbSlotVerifyTest, RollbackIndex) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 42,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  // First try with 42 as the stored rollback index - this should
  // succeed since the image rollback index is 42 (as set above).
  ops_.set_stored_rollback_indexes({42});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));

  // Then try with 43 for the stored rollback index - this should fail
  // because the image has rollback index 42 which is less than 43.
  ops_.set_stored_rollback_indexes({43});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));
}

TEST_F(AvbSlotVerifyTest, HashDescriptorInVBMeta) {
  const size_t boot_partition_size = 16 * 1024 * 1024;
  const size_t boot_image_size = 5 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", boot_image_size);

  EXPECT_COMMAND(
      0,
      "./avbtool add_hash_footer"
      " --image %s"
      " --rollback_index 0"
      " --partition_name boot"
      " --partition_size %zd"
      " --kernel_cmdline 'cmdline in hash footer $(ANDROID_SYSTEM_PARTUUID)'"
      " --salt deadbeef",
      boot_path.value().c_str(), boot_partition_size);

  GenerateVBMetaImage(
      "vbmeta_a.img", "SHA256_RSA2048", 4,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf(
          "--include_descriptors_from_image %s"
          " --kernel_cmdline 'cmdline in vbmeta $(ANDROID_BOOT_PARTUUID)'",
          boot_path.value().c_str()));

  EXPECT_EQ(
      "VBMeta image version:     1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     576 bytes\n"
      "Auxiliary Block:          768 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           4\n"
      "Descriptors:\n"
      "    Kernel Cmdline descriptor:\n"
      "      Kernel Cmdline:        'cmdline in vbmeta "
      "$(ANDROID_BOOT_PARTUUID)'\n"
      "    Hash descriptor:\n"
      "      Image Size:            5242880 bytes\n"
      "      Hash Algorithm:        sha256\n"
      "      Partition Name:        boot\n"
      "      Salt:                  deadbeef\n"
      "      Digest:                "
      "184cb36243adb8b87d2d8c4802de32125fe294ec46753d732144ee65df68a23d\n"
      "    Kernel Cmdline descriptor:\n"
      "      Kernel Cmdline:        'cmdline in hash footer "
      "$(ANDROID_SYSTEM_PARTUUID)'\n",
      InfoImage(vbmeta_image_path_));

  EXPECT_COMMAND(0,
                 "./avbtool erase_footer"
                 " --image %s",
                 boot_path.value().c_str());

  // With no footer, 'avbtool info_image' should fail (exit status 1).
  EXPECT_COMMAND(1, "./avbtool info_image --image %s",
                 boot_path.value().c_str());

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), "_a", &slot_data));
  EXPECT_NE(nullptr, slot_data);

  // Now verify the slot data. The vbmeta data should match our
  // vbmeta_image_ member.
  EXPECT_EQ(slot_data->vbmeta_size, vbmeta_image_.size());
  EXPECT_EQ(0, memcmp(vbmeta_image_.data(), slot_data->vbmeta_data,
                      slot_data->vbmeta_size));

  // The boot image data should match what is generated above with
  // GenerateImage().
  EXPECT_EQ(boot_image_size, slot_data->boot_size);
  for (size_t n = 0; n < slot_data->boot_size; n++) {
    EXPECT_EQ(slot_data->boot_data[n], uint8_t(n));
  }

  // This should match the two cmdlines with a space (U+0020) between
  // them and the $(ANDROID_SYSTEM_PARTUUID) and
  // $(ANDROID_BOOT_PARTUUID) variables replaced.
  EXPECT_EQ(
      "cmdline in vbmeta 1234-fake-guid-for:boot_a "
      "cmdline in hash footer 1234-fake-guid-for:system_a "
      "androidboot.slot_suffix=_a "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1600 "
      "androidboot.vbmeta.digest=844308149e43d5db7b14cd5747def40a",
      std::string(slot_data->cmdline));
  EXPECT_EQ(4UL, slot_data->rollback_indexes[0]);
  for (size_t n = 1; n < AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_SLOTS; n++) {
    EXPECT_EQ(0UL, slot_data->rollback_indexes[n]);
  }
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, HashDescriptorInVBMetaCorruptBoot) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", 5 * 1024 * 1024);

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --rollback_index 0"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --salt deadbeef",
                 boot_path.value().c_str(), boot_partition_size);

  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--include_descriptors_from_image %s",
                                         boot_path.value().c_str()));

  EXPECT_COMMAND(0,
                 "./avbtool erase_footer"
                 " --image %s",
                 boot_path.value().c_str());

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  // So far, so good.
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));

  // Now corrupt boot_a.img and expect verification error.
  uint8_t corrupt_data[4] = {0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(AVB_IO_RESULT_OK, ops_.avb_ops()->write_to_partition(
                                  ops_.avb_ops(), "boot_a",
                                  1024 * 1024,  // offset: 1 MiB
                                  sizeof corrupt_data, corrupt_data));

  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));
}

TEST_F(AvbSlotVerifyTest, HashDescriptorInChainedPartition) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  const size_t boot_image_size = 5 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", boot_image_size);

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --kernel_cmdline 'cmdline2 in hash footer'"
                 " --rollback_index 12"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --algorithm SHA256_RSA4096"
                 " --key test/data/testkey_rsa4096.pem"
                 " --salt deadbeef",
                 boot_path.value().c_str(), boot_partition_size);

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  GenerateVBMetaImage(
      "vbmeta_a.img", "SHA256_RSA2048", 11,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf("--chain_partition boot:1:%s"
                         " --kernel_cmdline 'cmdline2 in vbmeta'",
                         pk_path.value().c_str()));

  EXPECT_EQ(
      "VBMeta image version:     1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     576 bytes\n"
      "Auxiliary Block:          1664 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           11\n"
      "Descriptors:\n"
      "    Chain Partition descriptor:\n"
      "      Partition Name:        boot\n"
      "      Rollback Index Slot:   1\n"
      "      Public key (sha1):     2597c218aae470a130f61162feaae70afd97f011\n"
      "    Kernel Cmdline descriptor:\n"
      "      Kernel Cmdline:        'cmdline2 in vbmeta'\n",
      InfoImage(vbmeta_image_path_));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), "_a", &slot_data));
  EXPECT_NE(nullptr, slot_data);

  // Now verify the slot data. The vbmeta data should match our
  // vbmeta_image_ member.
  EXPECT_EQ(slot_data->vbmeta_size, vbmeta_image_.size());
  EXPECT_EQ(0, memcmp(vbmeta_image_.data(), slot_data->vbmeta_data,
                      slot_data->vbmeta_size));

  // The boot image data should match what is generated above with
  // GenerateImage().
  EXPECT_EQ(boot_image_size, slot_data->boot_size);
  for (size_t n = 0; n < slot_data->boot_size; n++) {
    EXPECT_EQ(slot_data->boot_data[n], uint8_t(n));
  }

  // This should match the two cmdlines with a space (U+0020) between them.
  EXPECT_EQ(
      "cmdline2 in hash footer cmdline2 in vbmeta "
      "androidboot.slot_suffix=_a "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=2496 "
      "androidboot.vbmeta.digest=3924a4e4cdf9a4e6e77b0d87e6e9b464",
      std::string(slot_data->cmdline));
  EXPECT_EQ(11UL, slot_data->rollback_indexes[0]);
  EXPECT_EQ(12UL, slot_data->rollback_indexes[1]);
  for (size_t n = 2; n < AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_SLOTS; n++) {
    EXPECT_EQ(0UL, slot_data->rollback_indexes[n]);
  }
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, HashDescriptorInChainedPartitionCorruptBoot) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", 5 * 1024 * 1024);

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --rollback_index 0"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --algorithm SHA256_RSA4096"
                 " --key test/data/testkey_rsa4096.pem"
                 " --salt deadbeef",
                 boot_path.value().c_str(), boot_partition_size);

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--chain_partition boot:1:%s",
                                         pk_path.value().c_str()));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));

  // Now corrupt boot_a.img and expect verification error.
  uint8_t corrupt_data[4] = {0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(AVB_IO_RESULT_OK, ops_.avb_ops()->write_to_partition(
                                  ops_.avb_ops(), "boot_a",
                                  1024 * 1024,  // offset: 1 MiB
                                  sizeof corrupt_data, corrupt_data));

  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));
}

TEST_F(AvbSlotVerifyTest, HashDescriptorInChainedPartitionKeyMismatch) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", 5 * 1024 * 1024);

  // Use different key to sign vbmeta in boot_a (we use the 8192 bit
  // key) than what's in the chained partition descriptor (which is
  // the 4096 bit key) and expect
  // AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED.

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --rollback_index 0"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --algorithm SHA256_RSA8192"
                 " --key test/data/testkey_rsa8192.pem"
                 " --salt deadbeef",
                 boot_path.value().c_str(), boot_partition_size);

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--chain_partition boot:1:%s",
                                         pk_path.value().c_str()));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));
}

TEST_F(AvbSlotVerifyTest, HashDescriptorInChainedPartitionRollbackIndexFail) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", 5 * 1024 * 1024);

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --rollback_index 10"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --algorithm SHA256_RSA4096"
                 " --key test/data/testkey_rsa4096.pem"
                 " --salt deadbeef",
                 boot_path.value().c_str(), boot_partition_size);

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 110,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--chain_partition boot:1:%s",
                                         pk_path.value().c_str()));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  // Both images (vbmeta_a and boot_a) have rollback index 10 and 11
  // so it should work if the stored rollback indexes are 0 and 0.
  ops_.set_stored_rollback_indexes({0, 0});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));

  // Check failure if we set the stored rollback index of the chained
  // partition to 20 (see AvbSlotVerifyTest.RollbackIndex above
  // where we test rollback index checks for the vbmeta partition).
  ops_.set_stored_rollback_indexes({0, 20});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));

  // Check failure if there is no rollback index slot 1 - in that case
  // we expect an I/O error since ops->read_rollback_index() will
  // fail.
  ops_.set_stored_rollback_indexes({0});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_IO,
            avb_slot_verify(ops_.avb_ops(), "_a", NULL));
}

TEST_F(AvbSlotVerifyTest, ChainedPartitionNoSlots) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  const size_t boot_image_size = 5 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot.img", boot_image_size);

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --kernel_cmdline 'cmdline2 in hash footer'"
                 " --rollback_index 12"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --algorithm SHA256_RSA4096"
                 " --key test/data/testkey_rsa4096.pem"
                 " --salt deadbeef",
                 boot_path.value().c_str(), boot_partition_size);

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  GenerateVBMetaImage(
      "vbmeta.img", "SHA256_RSA2048", 11,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf("--chain_partition boot:1:%s"
                         " --kernel_cmdline 'cmdline2 in vbmeta'",
                         pk_path.value().c_str()));

  EXPECT_EQ(
      "VBMeta image version:     1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     576 bytes\n"
      "Auxiliary Block:          1664 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           11\n"
      "Descriptors:\n"
      "    Chain Partition descriptor:\n"
      "      Partition Name:        boot\n"
      "      Rollback Index Slot:   1\n"
      "      Public key (sha1):     2597c218aae470a130f61162feaae70afd97f011\n"
      "    Kernel Cmdline descriptor:\n"
      "      Kernel Cmdline:        'cmdline2 in vbmeta'\n",
      InfoImage(vbmeta_image_path_));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), "", &slot_data));
  EXPECT_NE(nullptr, slot_data);

  // Now verify the slot data. The vbmeta data should match our
  // vbmeta_image_ member.
  EXPECT_EQ(slot_data->vbmeta_size, vbmeta_image_.size());
  EXPECT_EQ(0, memcmp(vbmeta_image_.data(), slot_data->vbmeta_data,
                      slot_data->vbmeta_size));

  // The boot image data should match what is generated above with
  // GenerateImage().
  EXPECT_EQ(boot_image_size, slot_data->boot_size);
  for (size_t n = 0; n < slot_data->boot_size; n++) {
    EXPECT_EQ(slot_data->boot_data[n], uint8_t(n));
  }

  // This should match the two cmdlines with a space (U+0020) between
  // them - note that androidboot.slot_suffix is not set since we
  // don't have any slots in this setup.
  EXPECT_EQ(
      "cmdline2 in hash footer cmdline2 in vbmeta "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=2496 "
      "androidboot.vbmeta.digest=3924a4e4cdf9a4e6e77b0d87e6e9b464",
      std::string(slot_data->cmdline));
  EXPECT_EQ(11UL, slot_data->rollback_indexes[0]);
  EXPECT_EQ(12UL, slot_data->rollback_indexes[1]);
  for (size_t n = 2; n < AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_SLOTS; n++) {
    EXPECT_EQ(0UL, slot_data->rollback_indexes[n]);
  }
  avb_slot_verify_data_free(slot_data);
}
