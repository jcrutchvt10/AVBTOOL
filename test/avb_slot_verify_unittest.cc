/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <iostream>

#include <base/files/file_util.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

#include "avb_unittest_util.h"
#include "fake_avb_ops.h"

namespace avb {

class AvbSlotVerifyTest : public BaseAvbToolTest {
 public:
  AvbSlotVerifyTest() {}

  virtual void SetUp() override {
    BaseAvbToolTest::SetUp();
    ops_.set_partition_dir(testdir_);
    ops_.set_stored_rollback_indexes({{0, 0}, {1, 0}, {2, 0}, {3, 0}});
    ops_.set_stored_is_device_unlocked(false);
  }

  void CmdlineWithHashtreeVerification(bool hashtree_verification_on);
  void CmdlineWithChainedHashtreeVerification(bool hashtree_verification_on);
  void VerificationDisabled(bool use_avbctl);

  FakeAvbOps ops_;
};

TEST_F(AvbSlotVerifyTest, Basic) {
  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      "--internal_release_string \"\"");

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
      "androidboot.vbmeta.avb_version=1.0 "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1152 "
      "androidboot.vbmeta.digest="
      "4161a7e655eabe16c3fe714de5d43736e7c0a190cf08d36c946d2509ce071e4d "
      "androidboot.vbmeta.invalidate_on_error=yes "
      "androidboot.veritymode=enforcing",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, BasicSha512) {
  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA512_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      "--internal_release_string \"\"");

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
      "androidboot.vbmeta.avb_version=1.0 "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha512 androidboot.vbmeta.size=1152 "
      "androidboot.vbmeta.digest="
      "cb913d2f1a884f4e04c1db5bb181f3133fd16ac02fb367a20ef0776c0b07b3656ad1f081"
      "e01932cf70f38b8960877470b448f1588dff022808387cc52fa77e77 "
      "androidboot.vbmeta.invalidate_on_error=yes "
      "androidboot.veritymode=enforcing",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, BasicUnlocked) {
  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      "--internal_release_string \"\"");

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  ops_.set_stored_is_device_unlocked(true);

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
      "androidboot.vbmeta.avb_version=1.0 "
      "androidboot.vbmeta.device_state=unlocked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1152 "
      "androidboot.vbmeta.digest="
      "4161a7e655eabe16c3fe714de5d43736e7c0a190cf08d36c946d2509ce071e4d "
      "androidboot.vbmeta.invalidate_on_error=yes "
      "androidboot.veritymode=enforcing",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, SlotDataIsCorrect) {
  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      "--internal_release_string \"\"");

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, WrongPublicKey) {
  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      "--internal_release_string \"\"");

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, NoImage) {
  const char* requested_partitions[] = {"boot", NULL};
  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_IO,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
}

TEST_F(AvbSlotVerifyTest, UnsignedVBMeta) {
  GenerateVBMetaImage("vbmeta_a.img",
                      "",
                      0,
                      base::FilePath(""),
                      "--internal_release_string \"\"");

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, CorruptedImage) {
  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      "--internal_release_string \"\"");

  // Corrupt four bytes of data in the end of the image. Since the aux
  // data is at the end and this data is signed, this will change the
  // value of the computed hash.
  uint8_t corrupt_data[4] = {0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(AVB_IO_RESULT_OK,
            ops_.avb_ops()->write_to_partition(ops_.avb_ops(),
                                               "vbmeta_a",
                                               -4,  // offset from end
                                               sizeof corrupt_data,
                                               corrupt_data));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, CorruptedMetadata) {
  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      "--internal_release_string \"\"");

  // Corrupt four bytes of data in the beginning of the image. Unlike
  // the CorruptedImage test-case above (which is valid metadata) this
  // will make the metadata invalid and render the slot unbootable
  // even if the device is unlocked. Specifically no AvbSlotVerifyData
  // is returned.
  uint8_t corrupt_data[4] = {0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(AVB_IO_RESULT_OK,
            ops_.avb_ops()->write_to_partition(ops_.avb_ops(),
                                               "vbmeta_a",
                                               0,  // offset: beginning
                                               sizeof corrupt_data,
                                               corrupt_data));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
}

TEST_F(AvbSlotVerifyTest, RollbackIndex) {
  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      42,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      "--internal_release_string \"\"");

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};

  // First try with 42 as the stored rollback index - this should
  // succeed since the image rollback index is 42 (as set above).
  ops_.set_stored_rollback_indexes({{0, 42}});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);

  // Then try with 43 for the stored rollback index - this should fail
  // because the image has rollback index 42 which is less than 43.
  ops_.set_stored_rollback_indexes({{0, 43}});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, LoadEntirePartitionIfAllowingVerificationError) {
  const size_t boot_partition_size = 16 * 1024 * 1024;
  const size_t boot_image_size = 5 * 1024 * 1024;
  const size_t new_boot_image_size = 10 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", boot_image_size);

  // If we're allowing verification errors then check that the whole
  // partition is loaded. This is needed because in this mode for
  // example the "boot" partition might be flashed with another
  // boot.img that is larger than what the HashDescriptor in vbmeta
  // says.
  EXPECT_COMMAND(
      0,
      "./avbtool add_hash_footer"
      " --image %s"
      " --rollback_index 0"
      " --partition_name boot"
      " --partition_size %zd"
      " --kernel_cmdline 'cmdline in hash footer $(ANDROID_SYSTEM_PARTUUID)'"
      " --salt deadbeef"
      " --internal_release_string \"\"",
      boot_path.value().c_str(),
      boot_partition_size);

  GenerateVBMetaImage(
      "vbmeta_a.img",
      "SHA256_RSA2048",
      4,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf(
          "--include_descriptors_from_image %s"
          " --kernel_cmdline 'cmdline in vbmeta $(ANDROID_BOOT_PARTUUID)'"
          " --internal_release_string \"\"",
          boot_path.value().c_str()));

  // Now replace the boot partition with something bigger and
  // different. Because FakeOps's get_size_of_partition() operation
  // just returns the file size it means that this is what is returned
  // by get_size_of_partition().
  //
  // Also make sure this image will return a different digest by using
  // a non-standard starting byte. This is to force avb_slot_verify()
  // to return ERROR_VERIFICATION below.
  GenerateImage("boot_a.img", new_boot_image_size, 1 /* start_byte */);

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);

  // Check that the loaded partition is actually
  // |new_boot_image_size|.
  EXPECT_EQ(size_t(1), slot_data->num_loaded_partitions);
  EXPECT_EQ("boot",
            std::string(slot_data->loaded_partitions[0].partition_name));
  EXPECT_EQ(new_boot_image_size, slot_data->loaded_partitions[0].data_size);
  avb_slot_verify_data_free(slot_data);
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
      " --salt deadbeef"
      " --internal_release_string \"\"",
      boot_path.value().c_str(),
      boot_partition_size);

  GenerateVBMetaImage(
      "vbmeta_a.img",
      "SHA256_RSA2048",
      4,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf(
          "--include_descriptors_from_image %s"
          " --kernel_cmdline 'cmdline in vbmeta $(ANDROID_BOOT_PARTUUID)'"
          " --internal_release_string \"\"",
          boot_path.value().c_str()));

  EXPECT_EQ(
      "Minimum libavb version:   1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     320 bytes\n"
      "Auxiliary Block:          896 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           4\n"
      "Flags:                    0\n"
      "Release String:           ''\n"
      "Descriptors:\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 0\n"
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
      "      Flags:                 0\n"
      "      Kernel Cmdline:        'cmdline in hash footer "
      "$(ANDROID_SYSTEM_PARTUUID)'\n",
      InfoImage(vbmeta_image_path_));

  EXPECT_COMMAND(0,
                 "./avbtool erase_footer"
                 " --image %s",
                 boot_path.value().c_str());

  // With no footer, 'avbtool info_image' should fail (exit status 1).
  EXPECT_COMMAND(
      1, "./avbtool info_image --image %s", boot_path.value().c_str());

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);

  // Now verify the slot data. The vbmeta data should match our
  // vbmeta_image_ member.
  EXPECT_EQ(size_t(1), slot_data->num_vbmeta_images);
  EXPECT_EQ("vbmeta", std::string(slot_data->vbmeta_images[0].partition_name));
  EXPECT_EQ(slot_data->vbmeta_images[0].vbmeta_size, vbmeta_image_.size());
  EXPECT_EQ(0,
            memcmp(vbmeta_image_.data(),
                   slot_data->vbmeta_images[0].vbmeta_data,
                   slot_data->vbmeta_images[0].vbmeta_size));

  // The boot image data should match what is generated above with
  // GenerateImage().
  EXPECT_EQ(size_t(1), slot_data->num_loaded_partitions);
  EXPECT_EQ("boot",
            std::string(slot_data->loaded_partitions[0].partition_name));
  EXPECT_EQ(boot_image_size, slot_data->loaded_partitions[0].data_size);
  for (size_t n = 0; n < slot_data->loaded_partitions[0].data_size; n++) {
    EXPECT_EQ(slot_data->loaded_partitions[0].data[n], uint8_t(n));
  }

  // This should match the two cmdlines with a space (U+0020) between
  // them and the $(ANDROID_SYSTEM_PARTUUID) and
  // $(ANDROID_BOOT_PARTUUID) variables replaced.
  EXPECT_EQ(
      "cmdline in vbmeta 1234-fake-guid-for:boot_a cmdline in hash footer "
      "1234-fake-guid-for:system_a "
      "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
      "androidboot.vbmeta.avb_version=1.0 "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1472 "
      "androidboot.vbmeta.digest="
      "34cdb59b955aa35d4da97701f304fabf7392eecca8c50ff1a0b7b6e1c9aaa1b8 "
      "androidboot.vbmeta.invalidate_on_error=yes "
      "androidboot.veritymode=enforcing",
      std::string(slot_data->cmdline));
  EXPECT_EQ(4UL, slot_data->rollback_indexes[0]);
  for (size_t n = 1; n < AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_LOCATIONS; n++) {
    EXPECT_EQ(0UL, slot_data->rollback_indexes[n]);
  }
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, HashDescriptorInVBMetaCorruptBoot) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", 5 * 1024 * 1024);
  const char* requested_partitions[] = {"boot", NULL};

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --rollback_index 0"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --salt deadbeef"
                 " --internal_release_string \"\"",
                 boot_path.value().c_str(),
                 boot_partition_size);

  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--include_descriptors_from_image %s"
                                         " --internal_release_string \"\"",
                                         boot_path.value().c_str()));

  EXPECT_COMMAND(0,
                 "./avbtool erase_footer"
                 " --image %s",
                 boot_path.value().c_str());

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  // So far, so good.
  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);

  // Now corrupt boot_a.img and expect verification error.
  uint8_t corrupt_data[4] = {0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(AVB_IO_RESULT_OK,
            ops_.avb_ops()->write_to_partition(ops_.avb_ops(),
                                               "boot_a",
                                               1024 * 1024,  // offset: 1 MiB
                                               sizeof corrupt_data,
                                               corrupt_data));

  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, HashDescriptorInChainedPartition) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  const size_t boot_image_size = 5 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", boot_image_size);
  const char* requested_partitions[] = {"boot", NULL};

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --kernel_cmdline 'cmdline2 in hash footer'"
                 " --rollback_index 12"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --algorithm SHA256_RSA4096"
                 " --key test/data/testkey_rsa4096.pem"
                 " --salt deadbeef"
                 " --internal_release_string \"\"",
                 boot_path.value().c_str(),
                 boot_partition_size);

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  GenerateVBMetaImage(
      "vbmeta_a.img",
      "SHA256_RSA2048",
      11,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf("--chain_partition boot:1:%s"
                         " --kernel_cmdline 'cmdline2 in vbmeta'"
                         " --internal_release_string \"\"",
                         pk_path.value().c_str()));

  EXPECT_EQ(
      "Minimum libavb version:   1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     320 bytes\n"
      "Auxiliary Block:          1728 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           11\n"
      "Flags:                    0\n"
      "Release String:           ''\n"
      "Descriptors:\n"
      "    Chain Partition descriptor:\n"
      "      Partition Name:          boot\n"
      "      Rollback Index Location: 1\n"
      "      Public key (sha1):       "
      "2597c218aae470a130f61162feaae70afd97f011\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 0\n"
      "      Kernel Cmdline:        'cmdline2 in vbmeta'\n",
      InfoImage(vbmeta_image_path_));

  EXPECT_EQ(
      "Footer version:           1.0\n"
      "Image size:               16777216 bytes\n"
      "Original image size:      5242880 bytes\n"
      "VBMeta offset:            5242880\n"
      "VBMeta size:              2112 bytes\n"
      "--\n"
      "Minimum libavb version:   1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     576 bytes\n"
      "Auxiliary Block:          1280 bytes\n"
      "Algorithm:                SHA256_RSA4096\n"
      "Rollback Index:           12\n"
      "Flags:                    0\n"
      "Release String:           ''\n"
      "Descriptors:\n"
      "    Hash descriptor:\n"
      "      Image Size:            5242880 bytes\n"
      "      Hash Algorithm:        sha256\n"
      "      Partition Name:        boot\n"
      "      Salt:                  deadbeef\n"
      "      Digest:                "
      "184cb36243adb8b87d2d8c4802de32125fe294ec46753d732144ee65df68a23d\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 0\n"
      "      Kernel Cmdline:        'cmdline2 in hash footer'\n",
      InfoImage(boot_path));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);

  // Now verify the slot data. We should have two vbmeta
  // structs. Verify both of them. Note that the A/B suffix isn't
  // appended.
  EXPECT_EQ(size_t(2), slot_data->num_vbmeta_images);
  EXPECT_EQ("vbmeta", std::string(slot_data->vbmeta_images[0].partition_name));
  EXPECT_EQ(slot_data->vbmeta_images[0].vbmeta_size, vbmeta_image_.size());
  EXPECT_EQ(0,
            memcmp(vbmeta_image_.data(),
                   slot_data->vbmeta_images[0].vbmeta_data,
                   slot_data->vbmeta_images[0].vbmeta_size));
  // And for the second vbmeta struct we check that the descriptors
  // match the info_image output from above.
  EXPECT_EQ("boot", std::string(slot_data->vbmeta_images[1].partition_name));
  const AvbDescriptor** descriptors =
      avb_descriptor_get_all(slot_data->vbmeta_images[1].vbmeta_data,
                             slot_data->vbmeta_images[1].vbmeta_size,
                             NULL);
  EXPECT_NE(nullptr, descriptors);
  AvbHashDescriptor hash_desc;
  EXPECT_EQ(true,
            avb_hash_descriptor_validate_and_byteswap(
                ((AvbHashDescriptor*)descriptors[0]), &hash_desc));
  const uint8_t* desc_end = reinterpret_cast<const uint8_t*>(descriptors[0]) +
                            sizeof(AvbHashDescriptor);
  uint64_t o = 0;
  EXPECT_EQ("boot",
            std::string(reinterpret_cast<const char*>(desc_end + o),
                        hash_desc.partition_name_len));
  o += hash_desc.partition_name_len;
  EXPECT_EQ("deadbeef", mem_to_hexstring(desc_end + o, hash_desc.salt_len));
  o += hash_desc.salt_len;
  EXPECT_EQ("184cb36243adb8b87d2d8c4802de32125fe294ec46753d732144ee65df68a23d",
            mem_to_hexstring(desc_end + o, hash_desc.digest_len));
  AvbKernelCmdlineDescriptor cmdline_desc;
  EXPECT_EQ(true,
            avb_kernel_cmdline_descriptor_validate_and_byteswap(
                ((AvbKernelCmdlineDescriptor*)descriptors[1]), &cmdline_desc));
  desc_end = reinterpret_cast<const uint8_t*>(descriptors[1]) +
             sizeof(AvbKernelCmdlineDescriptor);
  EXPECT_EQ("cmdline2 in hash footer",
            std::string(reinterpret_cast<const char*>(desc_end),
                        cmdline_desc.kernel_cmdline_length));
  avb_free(descriptors);

  // The boot image data should match what is generated above with
  // GenerateImage().
  EXPECT_EQ(size_t(1), slot_data->num_loaded_partitions);
  EXPECT_EQ("boot",
            std::string(slot_data->loaded_partitions[0].partition_name));
  EXPECT_EQ(boot_image_size, slot_data->loaded_partitions[0].data_size);
  for (size_t n = 0; n < slot_data->loaded_partitions[0].data_size; n++) {
    EXPECT_EQ(slot_data->loaded_partitions[0].data[n], uint8_t(n));
  }

  // This should match the two cmdlines with a space (U+0020) between them.
  EXPECT_EQ(
      "cmdline2 in hash footer cmdline2 in vbmeta "
      "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
      "androidboot.vbmeta.avb_version=1.0 "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=4416 "
      "androidboot.vbmeta.digest="
      "4a45faa9adfeb94e9154fe682c11fef1a1a3d829b67cbf1a12ac7f0aa4f8e2e4 "
      "androidboot.vbmeta.invalidate_on_error=yes "
      "androidboot.veritymode=enforcing",
      std::string(slot_data->cmdline));
  EXPECT_EQ(11UL, slot_data->rollback_indexes[0]);
  EXPECT_EQ(12UL, slot_data->rollback_indexes[1]);
  for (size_t n = 2; n < AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_LOCATIONS; n++) {
    EXPECT_EQ(0UL, slot_data->rollback_indexes[n]);
  }
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, HashDescriptorInChainedPartitionCorruptBoot) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", 5 * 1024 * 1024);
  const char* requested_partitions[] = {"boot", NULL};

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --rollback_index 0"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --algorithm SHA256_RSA4096"
                 " --key test/data/testkey_rsa4096.pem"
                 " --salt deadbeef"
                 " --internal_release_string \"\"",
                 boot_path.value().c_str(),
                 boot_partition_size);

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--chain_partition boot:1:%s"
                                         " --internal_release_string \"\"",
                                         pk_path.value().c_str()));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);

  // Now corrupt boot_a.img and expect verification error.
  uint8_t corrupt_data[4] = {0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(AVB_IO_RESULT_OK,
            ops_.avb_ops()->write_to_partition(ops_.avb_ops(),
                                               "boot_a",
                                               1024 * 1024,  // offset: 1 MiB
                                               sizeof corrupt_data,
                                               corrupt_data));

  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, HashDescriptorInChainedPartitionKeyMismatch) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", 5 * 1024 * 1024);
  const char* requested_partitions[] = {"boot", NULL};

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
                 " --salt deadbeef"
                 " --internal_release_string \"\"",
                 boot_path.value().c_str(),
                 boot_partition_size);

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--chain_partition boot:1:%s"
                                         " --internal_release_string \"\"",
                                         pk_path.value().c_str()));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, HashDescriptorInChainedPartitionRollbackIndexFail) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", 5 * 1024 * 1024);
  const char* requested_partitions[] = {"boot", NULL};

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --rollback_index 10"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --algorithm SHA256_RSA4096"
                 " --key test/data/testkey_rsa4096.pem"
                 " --salt deadbeef"
                 " --internal_release_string \"\"",
                 boot_path.value().c_str(),
                 boot_partition_size);

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      110,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--chain_partition boot:1:%s"
                                         " --internal_release_string \"\"",
                                         pk_path.value().c_str()));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;

  // Both images (vbmeta_a and boot_a) have rollback index 10 and 11
  // so it should work if the stored rollback indexes are 0 and 0.
  ops_.set_stored_rollback_indexes({{0, 0}, {1, 0}});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);

  // Check failure if we set the stored rollback index of the chained
  // partition to 20 (see AvbSlotVerifyTest.RollbackIndex above
  // where we test rollback index checks for the vbmeta partition).
  ops_.set_stored_rollback_indexes({{0, 0}, {1, 20}});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);

  // Check failure if there is no rollback index slot 1 - in that case
  // we expect an I/O error since ops->read_rollback_index() will
  // fail.
  ops_.set_stored_rollback_indexes({{0, 0}});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_IO,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
}

TEST_F(AvbSlotVerifyTest, ChainedPartitionNoSlots) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  const size_t boot_image_size = 5 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot.img", boot_image_size);
  const char* requested_partitions[] = {"boot", NULL};

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --kernel_cmdline 'cmdline2 in hash footer'"
                 " --rollback_index 12"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --algorithm SHA256_RSA4096"
                 " --key test/data/testkey_rsa4096.pem"
                 " --salt deadbeef"
                 " --internal_release_string \"\"",
                 boot_path.value().c_str(),
                 boot_partition_size);

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  GenerateVBMetaImage(
      "vbmeta.img",
      "SHA256_RSA2048",
      11,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf("--chain_partition boot:1:%s"
                         " --kernel_cmdline 'cmdline2 in vbmeta'"
                         " --internal_release_string \"\"",
                         pk_path.value().c_str()));

  EXPECT_EQ(
      "Minimum libavb version:   1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     320 bytes\n"
      "Auxiliary Block:          1728 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           11\n"
      "Flags:                    0\n"
      "Release String:           ''\n"
      "Descriptors:\n"
      "    Chain Partition descriptor:\n"
      "      Partition Name:          boot\n"
      "      Rollback Index Location: 1\n"
      "      Public key (sha1):       "
      "2597c218aae470a130f61162feaae70afd97f011\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 0\n"
      "      Kernel Cmdline:        'cmdline2 in vbmeta'\n",
      InfoImage(vbmeta_image_path_));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);

  // Now verify the slot data. The first vbmeta data should match our
  // vbmeta_image_ member and the second one should be for the 'boot'
  // partition.
  EXPECT_EQ(size_t(2), slot_data->num_vbmeta_images);
  EXPECT_EQ("vbmeta", std::string(slot_data->vbmeta_images[0].partition_name));
  EXPECT_EQ(slot_data->vbmeta_images[0].vbmeta_size, vbmeta_image_.size());
  EXPECT_EQ(0,
            memcmp(vbmeta_image_.data(),
                   slot_data->vbmeta_images[0].vbmeta_data,
                   slot_data->vbmeta_images[0].vbmeta_size));
  EXPECT_EQ("boot", std::string(slot_data->vbmeta_images[1].partition_name));

  // The boot image data should match what is generated above with
  // GenerateImage().
  EXPECT_EQ(size_t(1), slot_data->num_loaded_partitions);
  EXPECT_EQ("boot",
            std::string(slot_data->loaded_partitions[0].partition_name));
  EXPECT_EQ(boot_image_size, slot_data->loaded_partitions[0].data_size);
  for (size_t n = 0; n < slot_data->loaded_partitions[0].data_size; n++) {
    EXPECT_EQ(slot_data->loaded_partitions[0].data[n], uint8_t(n));
  }

  // This should match the two cmdlines with a space (U+0020) between
  // them.
  EXPECT_EQ(
      "cmdline2 in hash footer cmdline2 in vbmeta "
      "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
      "androidboot.vbmeta.avb_version=1.0 "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=4416 "
      "androidboot.vbmeta.digest="
      "4a45faa9adfeb94e9154fe682c11fef1a1a3d829b67cbf1a12ac7f0aa4f8e2e4 "
      "androidboot.vbmeta.invalidate_on_error=yes "
      "androidboot.veritymode=enforcing",
      std::string(slot_data->cmdline));
  EXPECT_EQ(11UL, slot_data->rollback_indexes[0]);
  EXPECT_EQ(12UL, slot_data->rollback_indexes[1]);
  for (size_t n = 2; n < AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_LOCATIONS; n++) {
    EXPECT_EQ(0UL, slot_data->rollback_indexes[n]);
  }
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, PartitionsOtherThanBoot) {
  const size_t foo_partition_size = 16 * 1024 * 1024;
  const size_t bar_partition_size = 32 * 1024 * 1024;
  const size_t foo_image_size = 5 * 1024 * 1024;
  const size_t bar_image_size = 10 * 1024 * 1024;
  base::FilePath foo_path = GenerateImage("foo_a.img", foo_image_size);
  base::FilePath bar_path = GenerateImage("bar_a.img", bar_image_size);

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --partition_name foo"
                 " --partition_size %zd"
                 " --salt deadbeef"
                 " --internal_release_string \"\"",
                 foo_path.value().c_str(),
                 foo_partition_size);

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --partition_name bar"
                 " --partition_size %zd"
                 " --salt deadbeef"
                 " --internal_release_string \"\"",
                 bar_path.value().c_str(),
                 bar_partition_size);

  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      4,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--include_descriptors_from_image %s"
                                         " --include_descriptors_from_image %s"
                                         " --internal_release_string \"\"",
                                         foo_path.value().c_str(),
                                         bar_path.value().c_str()));

  EXPECT_EQ(
      "Minimum libavb version:   1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     320 bytes\n"
      "Auxiliary Block:          896 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           4\n"
      "Flags:                    0\n"
      "Release String:           ''\n"
      "Descriptors:\n"
      "    Hash descriptor:\n"
      "      Image Size:            5242880 bytes\n"
      "      Hash Algorithm:        sha256\n"
      "      Partition Name:        foo\n"
      "      Salt:                  deadbeef\n"
      "      Digest:                "
      "184cb36243adb8b87d2d8c4802de32125fe294ec46753d732144ee65df68a23d\n"
      "    Hash descriptor:\n"
      "      Image Size:            10485760 bytes\n"
      "      Hash Algorithm:        sha256\n"
      "      Partition Name:        bar\n"
      "      Salt:                  deadbeef\n"
      "      Digest:                "
      "baea4bbd261d0edf4d1fe5e6e5a36976c291eeba66b6a46fa81dba691327a727\n",
      InfoImage(vbmeta_image_path_));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"foo", "bar", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);

  // Now verify the slot data. The vbmeta data should match our
  // vbmeta_image_ member.
  EXPECT_EQ(size_t(1), slot_data->num_vbmeta_images);
  EXPECT_EQ("vbmeta", std::string(slot_data->vbmeta_images[0].partition_name));
  EXPECT_EQ(slot_data->vbmeta_images[0].vbmeta_size, vbmeta_image_.size());
  EXPECT_EQ(0,
            memcmp(vbmeta_image_.data(),
                   slot_data->vbmeta_images[0].vbmeta_data,
                   slot_data->vbmeta_images[0].vbmeta_size));

  // The 'foo' and 'bar' image data should match what is generated
  // above with GenerateImage().
  EXPECT_EQ(size_t(2), slot_data->num_loaded_partitions);
  EXPECT_EQ("foo", std::string(slot_data->loaded_partitions[0].partition_name));
  EXPECT_EQ(foo_image_size, slot_data->loaded_partitions[0].data_size);
  for (size_t n = 0; n < slot_data->loaded_partitions[0].data_size; n++) {
    EXPECT_EQ(slot_data->loaded_partitions[0].data[n], uint8_t(n));
  }
  EXPECT_EQ("bar", std::string(slot_data->loaded_partitions[1].partition_name));
  EXPECT_EQ(bar_image_size, slot_data->loaded_partitions[1].data_size);
  for (size_t n = 0; n < slot_data->loaded_partitions[1].data_size; n++) {
    EXPECT_EQ(slot_data->loaded_partitions[1].data[n], uint8_t(n));
  }
  avb_slot_verify_data_free(slot_data);

  // Check that we loaded vbmeta_a, foo_a, and bar_a.
  std::set<std::string> partitions = ops_.get_partition_names_read_from();
  EXPECT_EQ(size_t(3), partitions.size());
  EXPECT_TRUE(partitions.find("vbmeta_a") != partitions.end());
  EXPECT_TRUE(partitions.find("foo_a") != partitions.end());
  EXPECT_TRUE(partitions.find("bar_a") != partitions.end());
}

TEST_F(AvbSlotVerifyTest, OnlyLoadWhatHasBeenRequested) {
  const size_t foo_partition_size = 16 * 1024 * 1024;
  const size_t bar_partition_size = 32 * 1024 * 1024;
  const size_t foo_image_size = 5 * 1024 * 1024;
  const size_t bar_image_size = 10 * 1024 * 1024;
  base::FilePath foo_path = GenerateImage("foo_a.img", foo_image_size);
  base::FilePath bar_path = GenerateImage("bar_a.img", bar_image_size);

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --partition_name foo"
                 " --partition_size %zd"
                 " --salt deadbeef"
                 " --internal_release_string \"\"",
                 foo_path.value().c_str(),
                 foo_partition_size);

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --partition_name bar"
                 " --partition_size %zd"
                 " --salt deadbeef"
                 " --internal_release_string \"\"",
                 bar_path.value().c_str(),
                 bar_partition_size);

  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      4,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--include_descriptors_from_image %s"
                                         " --include_descriptors_from_image %s"
                                         " --internal_release_string \"\"",
                                         foo_path.value().c_str(),
                                         bar_path.value().c_str()));

  EXPECT_EQ(
      "Minimum libavb version:   1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     320 bytes\n"
      "Auxiliary Block:          896 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           4\n"
      "Flags:                    0\n"
      "Release String:           ''\n"
      "Descriptors:\n"
      "    Hash descriptor:\n"
      "      Image Size:            5242880 bytes\n"
      "      Hash Algorithm:        sha256\n"
      "      Partition Name:        foo\n"
      "      Salt:                  deadbeef\n"
      "      Digest:                "
      "184cb36243adb8b87d2d8c4802de32125fe294ec46753d732144ee65df68a23d\n"
      "    Hash descriptor:\n"
      "      Image Size:            10485760 bytes\n"
      "      Hash Algorithm:        sha256\n"
      "      Partition Name:        bar\n"
      "      Salt:                  deadbeef\n"
      "      Digest:                "
      "baea4bbd261d0edf4d1fe5e6e5a36976c291eeba66b6a46fa81dba691327a727\n",
      InfoImage(vbmeta_image_path_));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));
  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"foo", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(size_t(1), slot_data->num_loaded_partitions);
  EXPECT_EQ("foo", std::string(slot_data->loaded_partitions[0].partition_name));
  avb_slot_verify_data_free(slot_data);

  // Check that we loaded vbmeta_a, foo_a but not bar_a.
  std::set<std::string> partitions = ops_.get_partition_names_read_from();
  EXPECT_EQ(size_t(2), partitions.size());
  EXPECT_TRUE(partitions.find("vbmeta_a") != partitions.end());
  EXPECT_TRUE(partitions.find("foo_a") != partitions.end());
  EXPECT_TRUE(partitions.find("bar_a") == partitions.end());
}

TEST_F(AvbSlotVerifyTest, PublicKeyMetadata) {
  base::FilePath md_path = GenerateImage("md.bin", 1536);

  GenerateVBMetaImage("vbmeta_a.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--public_key_metadata %s"
                                         " --internal_release_string \"\"",
                                         md_path.value().c_str()));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  std::string md_data;
  ASSERT_TRUE(base::ReadFileToString(md_path, &md_data));
  ops_.set_expected_public_key_metadata(md_data);

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
      "androidboot.vbmeta.avb_version=1.0 "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=2688 "
      "androidboot.vbmeta.digest="
      "5edcaa54f40382ee6a2fc3b86cdf383348b35ed07955e83ea32d84b69a97eaa0 "
      "androidboot.vbmeta.invalidate_on_error=yes "
      "androidboot.veritymode=enforcing",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);
}

void AvbSlotVerifyTest::CmdlineWithHashtreeVerification(
    bool hashtree_verification_on) {
  const size_t rootfs_size = 1028 * 1024;
  const size_t partition_size = 1536 * 1024;

  // Generate a 1028 KiB file with known content.
  std::vector<uint8_t> rootfs;
  rootfs.resize(rootfs_size);
  for (size_t n = 0; n < rootfs_size; n++)
    rootfs[n] = uint8_t(n);
  base::FilePath rootfs_path = testdir_.Append("rootfs.bin");
  EXPECT_EQ(rootfs_size,
            static_cast<const size_t>(
                base::WriteFile(rootfs_path,
                                reinterpret_cast<const char*>(rootfs.data()),
                                rootfs.size())));

  EXPECT_COMMAND(0,
                 "./avbtool add_hashtree_footer --salt d00df00d --image %s "
                 "--partition_size %d --partition_name foobar "
                 "--algorithm SHA256_RSA2048 "
                 "--key test/data/testkey_rsa2048.pem "
                 "--internal_release_string \"\" "
                 "--do_not_generate_fec",
                 rootfs_path.value().c_str(),
                 (int)partition_size);

  // Check that we correctly generate dm-verity kernel cmdline
  // snippets, if requested.
  GenerateVBMetaImage(
      "vbmeta_a.img",
      "SHA256_RSA2048",
      4,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf("--setup_rootfs_from_kernel %s "
                         "--kernel_cmdline should_be_in_both=1 "
                         "--algorithm SHA256_RSA2048 "
                         "--flags %d "
                         "--internal_release_string \"\"",
                         rootfs_path.value().c_str(),
                         hashtree_verification_on
                             ? 0
                             : AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED));

  EXPECT_EQ(
      base::StringPrintf(
          "Minimum libavb version:   1.0\n"
          "Header Block:             256 bytes\n"
          "Authentication Block:     320 bytes\n"
          "Auxiliary Block:          960 bytes\n"
          "Algorithm:                SHA256_RSA2048\n"
          "Rollback Index:           4\n"
          "Flags:                    %d\n"
          "Release String:           ''\n"
          "Descriptors:\n"
          "    Kernel Cmdline descriptor:\n"
          "      Flags:                 1\n"
          "      Kernel Cmdline:        'dm=\"1 vroot none ro 1,0 2056 verity "
          "1 PARTUUID=$(ANDROID_SYSTEM_PARTUUID) "
          "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) 4096 4096 257 257 sha1 "
          "e811611467dcd6e8dc4324e45f706c2bdd51db67 d00df00d 2 "
          "$(ANDROID_VERITY_MODE) ignore_zero_blocks\" root=/dev/dm-0'\n"
          "    Kernel Cmdline descriptor:\n"
          "      Flags:                 2\n"
          "      Kernel Cmdline:        "
          "'root=PARTUUID=$(ANDROID_SYSTEM_PARTUUID)'\n"
          "    Kernel Cmdline descriptor:\n"
          "      Flags:                 0\n"
          "      Kernel Cmdline:        'should_be_in_both=1'\n",
          hashtree_verification_on ? 0
                                   : AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED),
      InfoImage(vbmeta_image_path_));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  // Check that avb_slot_verify() picks the cmdline decsriptors based
  // on their flags value.
  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  if (hashtree_verification_on) {
    EXPECT_EQ(
        "dm=\"1 vroot none ro 1,0 2056 verity 1 "
        "PARTUUID=1234-fake-guid-for:system_a "
        "PARTUUID=1234-fake-guid-for:system_a 4096 4096 257 257 sha1 "
        "e811611467dcd6e8dc4324e45f706c2bdd51db67 d00df00d 2 "
        "restart_on_corruption ignore_zero_blocks\" root=/dev/dm-0 "
        "should_be_in_both=1 "
        "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
        "androidboot.vbmeta.avb_version=1.0 "
        "androidboot.vbmeta.device_state=locked "
        "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1536 "
        "androidboot.vbmeta.digest="
        "946996b4cd78f2c060f6bb062b94054b809cbfbe9bf4425df263a0e55395ceea "
        "androidboot.vbmeta.invalidate_on_error=yes "
        "androidboot.veritymode=enforcing",
        std::string(slot_data->cmdline));
  } else {
    // NOTE: androidboot.veritymode is 'disabled', not 'enforcing' and
    // androidboot.vbmeta.invalidate_on_error isn't set.
    EXPECT_EQ(
        "root=PARTUUID=1234-fake-guid-for:system_a should_be_in_both=1 "
        "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
        "androidboot.vbmeta.avb_version=1.0 "
        "androidboot.vbmeta.device_state=locked "
        "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1536 "
        "androidboot.vbmeta.digest="
        "c74338b2b366f7f774d264abb4ac06c997cbaacbf5edd70a6ef1a552f744076b "
        "androidboot.veritymode=disabled",
        std::string(slot_data->cmdline));
  }
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, CmdlineWithHashtreeVerificationOff) {
  CmdlineWithHashtreeVerification(false);
}

TEST_F(AvbSlotVerifyTest, CmdlineWithHashtreeVerificationOn) {
  CmdlineWithHashtreeVerification(true);
}

void AvbSlotVerifyTest::CmdlineWithChainedHashtreeVerification(
    bool hashtree_verification_on) {
  const size_t system_size = 1028 * 1024;
  const size_t system_partition_size = 1536 * 1024;

  // Generate a 1028 KiB file with known content.
  std::vector<uint8_t> contents;
  contents.resize(system_size);
  for (size_t n = 0; n < system_size; n++)
    contents[n] = uint8_t(n);
  base::FilePath system_path = testdir_.Append("system_a.img");
  EXPECT_EQ(system_size,
            static_cast<const size_t>(
                base::WriteFile(system_path,
                                reinterpret_cast<const char*>(contents.data()),
                                contents.size())));

  // Check that we correctly generate dm-verity kernel cmdline
  // snippets, if requested.
  EXPECT_COMMAND(0,
                 "./avbtool add_hashtree_footer --salt d00df00d --image %s "
                 "--partition_size %d --partition_name foobar "
                 "--algorithm SHA256_RSA2048 "
                 "--key test/data/testkey_rsa2048.pem "
                 "--internal_release_string \"\" "
                 "--do_not_generate_fec "
                 "--setup_as_rootfs_from_kernel",
                 system_path.value().c_str(),
                 (int)system_partition_size);

  EXPECT_EQ(
      "Footer version:           1.0\n"
      "Image size:               1572864 bytes\n"
      "Original image size:      1052672 bytes\n"
      "VBMeta offset:            1069056\n"
      "VBMeta size:              1664 bytes\n"
      "--\n"
      "Minimum libavb version:   1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     320 bytes\n"
      "Auxiliary Block:          1088 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           0\n"
      "Flags:                    0\n"
      "Release String:           ''\n"
      "Descriptors:\n"
      "    Hashtree descriptor:\n"
      "      Version of dm-verity:  1\n"
      "      Image Size:            1052672 bytes\n"
      "      Tree Offset:           1052672\n"
      "      Tree Size:             16384 bytes\n"
      "      Data Block Size:       4096 bytes\n"
      "      Hash Block Size:       4096 bytes\n"
      "      FEC num roots:         0\n"
      "      FEC offset:            0\n"
      "      FEC size:              0 bytes\n"
      "      Hash Algorithm:        sha1\n"
      "      Partition Name:        foobar\n"
      "      Salt:                  d00df00d\n"
      "      Root Digest:           e811611467dcd6e8dc4324e45f706c2bdd51db67\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 1\n"
      "      Kernel Cmdline:        'dm=\"1 vroot none ro 1,0 2056 verity 1 "
      "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) PARTUUID=$(ANDROID_SYSTEM_PARTUUID) "
      "4096 4096 257 257 sha1 e811611467dcd6e8dc4324e45f706c2bdd51db67 "
      "d00df00d 2 $(ANDROID_VERITY_MODE) ignore_zero_blocks\" root=/dev/dm-0'\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 2\n"
      "      Kernel Cmdline:        "
      "'root=PARTUUID=$(ANDROID_SYSTEM_PARTUUID)'\n",
      InfoImage(system_path));

  base::FilePath pk_path = testdir_.Append("testkey_rsa2048.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa2048.pem"
      " --output %s",
      pk_path.value().c_str());

  GenerateVBMetaImage(
      "vbmeta_a.img",
      "SHA256_RSA2048",
      4,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf("--kernel_cmdline should_be_in_both=1 "
                         "--algorithm SHA256_RSA2048 "
                         "--flags %d "
                         "--chain_partition system:1:%s "
                         "--internal_release_string \"\"",
                         hashtree_verification_on
                             ? 0
                             : AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED,
                         pk_path.value().c_str()));

  EXPECT_EQ(
      base::StringPrintf("Minimum libavb version:   1.0\n"
                         "Header Block:             256 bytes\n"
                         "Authentication Block:     320 bytes\n"
                         "Auxiliary Block:          1216 bytes\n"
                         "Algorithm:                SHA256_RSA2048\n"
                         "Rollback Index:           4\n"
                         "Flags:                    %d\n"
                         "Release String:           ''\n"
                         "Descriptors:\n"
                         "    Chain Partition descriptor:\n"
                         "      Partition Name:          system\n"
                         "      Rollback Index Location: 1\n"
                         "      Public key (sha1):       "
                         "cdbb77177f731920bbe0a0f94f84d9038ae0617d\n"
                         "    Kernel Cmdline descriptor:\n"
                         "      Flags:                 0\n"
                         "      Kernel Cmdline:        'should_be_in_both=1'\n",
                         hashtree_verification_on
                             ? 0
                             : AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED),
      InfoImage(vbmeta_image_path_));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  // Check that avb_slot_verify() picks the cmdline descriptors based
  // on their flags value... note that these descriptors are in the
  // 'system' partition.
  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  if (hashtree_verification_on) {
    EXPECT_EQ(
        "dm=\"1 vroot none ro 1,0 2056 verity 1 "
        "PARTUUID=1234-fake-guid-for:system_a "
        "PARTUUID=1234-fake-guid-for:system_a 4096 4096 257 257 sha1 "
        "e811611467dcd6e8dc4324e45f706c2bdd51db67 d00df00d 2 "
        "restart_on_corruption ignore_zero_blocks\" root=/dev/dm-0 "
        "should_be_in_both=1 "
        "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
        "androidboot.vbmeta.avb_version=1.0 "
        "androidboot.vbmeta.device_state=locked "
        "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=3456 "
        "androidboot.vbmeta.digest="
        "5ee1669b112625322657b83ec932c73dad9b0222011b5aa3e8273f4e0ee025dc "
        "androidboot.vbmeta.invalidate_on_error=yes "
        "androidboot.veritymode=enforcing",
        std::string(slot_data->cmdline));
  } else {
    // NOTE: androidboot.veritymode is 'disabled', not 'enforcing' and
    // androidboot.vbmeta.invalidate_on_error isn't set.
    EXPECT_EQ(
        "root=PARTUUID=1234-fake-guid-for:system_a should_be_in_both=1 "
        "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
        "androidboot.vbmeta.avb_version=1.0 "
        "androidboot.vbmeta.device_state=locked "
        "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=3456 "
        "androidboot.vbmeta.digest="
        "ae792c45a9d898b532ff9625b60043a8d9eae7e6106b9cba31837d50ba40f81c "
        "androidboot.veritymode=disabled",
        std::string(slot_data->cmdline));
  }
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, CmdlineWithChainedHashtreeVerificationOff) {
  CmdlineWithChainedHashtreeVerification(false);
}

TEST_F(AvbSlotVerifyTest, CmdlineWithChainedHashtreeVerificationOn) {
  CmdlineWithChainedHashtreeVerification(true);
}

void AvbSlotVerifyTest::VerificationDisabled(bool use_avbctl) {
  const size_t boot_part_size = 32 * 1024 * 1024;
  const size_t dtbo_part_size = 4 * 1024 * 1024;
  const size_t rootfs_size = 1028 * 1024;
  const size_t partition_size = 1536 * 1024;

  // Generate boot_a.img and dtbo_a.img since avb_slot_verify() will
  // attempt to load them upon encountering the VERIFICATION_DISABLED
  // flag.
  base::FilePath boot_path = GenerateImage("boot_a.img", boot_part_size);
  const size_t DTBO_DATA_OFFSET = 42;
  base::FilePath dtbo_path =
      GenerateImage("dtbo_a.img", dtbo_part_size, DTBO_DATA_OFFSET);

  // Generate a 1028 KiB file with known content.
  std::vector<uint8_t> rootfs;
  rootfs.resize(rootfs_size);
  for (size_t n = 0; n < rootfs_size; n++)
    rootfs[n] = uint8_t(n);
  base::FilePath rootfs_path = testdir_.Append("rootfs.bin");
  EXPECT_EQ(rootfs_size,
            static_cast<const size_t>(
                base::WriteFile(rootfs_path,
                                reinterpret_cast<const char*>(rootfs.data()),
                                rootfs.size())));

  EXPECT_COMMAND(0,
                 "./avbtool add_hashtree_footer --salt d00df00d --image %s "
                 "--partition_size %d --partition_name foobar "
                 "--algorithm SHA256_RSA2048 "
                 "--key test/data/testkey_rsa2048.pem "
                 "--internal_release_string \"\" "
                 "--do_not_generate_fec",
                 rootfs_path.value().c_str(),
                 (int)partition_size);

  // Check that we correctly generate dm-verity kernel cmdline
  // snippets, if requested.
  GenerateVBMetaImage(
      "vbmeta_a.img",
      "SHA256_RSA2048",
      4,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf(
          "--setup_rootfs_from_kernel %s "
          "--kernel_cmdline should_be_in_both=1 "
          "--algorithm SHA256_RSA2048 "
          "--flags %d "
          "--internal_release_string \"\"",
          rootfs_path.value().c_str(),
          use_avbctl ? 0 : AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED));

  EXPECT_EQ(
      base::StringPrintf(
          "Minimum libavb version:   1.0\n"
          "Header Block:             256 bytes\n"
          "Authentication Block:     320 bytes\n"
          "Auxiliary Block:          960 bytes\n"
          "Algorithm:                SHA256_RSA2048\n"
          "Rollback Index:           4\n"
          "Flags:                    %d\n"
          "Release String:           ''\n"
          "Descriptors:\n"
          "    Kernel Cmdline descriptor:\n"
          "      Flags:                 1\n"
          "      Kernel Cmdline:        'dm=\"1 vroot none ro 1,0 2056 verity "
          "1 PARTUUID=$(ANDROID_SYSTEM_PARTUUID) "
          "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) 4096 4096 257 257 sha1 "
          "e811611467dcd6e8dc4324e45f706c2bdd51db67 d00df00d 2 "
          "$(ANDROID_VERITY_MODE) ignore_zero_blocks\" root=/dev/dm-0'\n"
          "    Kernel Cmdline descriptor:\n"
          "      Flags:                 2\n"
          "      Kernel Cmdline:        "
          "'root=PARTUUID=$(ANDROID_SYSTEM_PARTUUID)'\n"
          "    Kernel Cmdline descriptor:\n"
          "      Flags:                 0\n"
          "      Kernel Cmdline:        'should_be_in_both=1'\n",
          use_avbctl ? 0 : AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED),
      InfoImage(vbmeta_image_path_));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  // Manually set the flag the same way 'avbctl disable-verification'
  // would do it.
  if (use_avbctl) {
    uint32_t flags_data;
    flags_data = avb_htobe32(AVB_VBMETA_IMAGE_FLAGS_VERIFICATION_DISABLED);
    EXPECT_EQ(AVB_IO_RESULT_OK,
              ops_.avb_ops()->write_to_partition(
                  ops_.avb_ops(),
                  "vbmeta_a",
                  offsetof(AvbVBMetaImageHeader, flags),
                  sizeof flags_data,
                  &flags_data));
  }

  // Check that avb_slot_verify() doesn't return any of the
  // descriptors and instead return a kernel command-line with
  // root=PARTUUID=<whatever_for_system_a> and none of the
  // androidboot.vbmeta.* options are set. Also ensure all the
  // requested partitions are loaded.
  //
  // Also if we modified via avbctl we should expect
  // ERROR_VERIFICATION instead of OK.
  //
  AvbSlotVerifyResult expected_result = AVB_SLOT_VERIFY_RESULT_OK;
  if (use_avbctl) {
    expected_result = AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION;
  }
  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", "dtbo", NULL};
  EXPECT_EQ(expected_result,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ("root=PARTUUID=1234-fake-guid-for:system_a",
            std::string(slot_data->cmdline));
  // Also make sure that it actually loads the boot and dtbo partitions.
  EXPECT_EQ(size_t(2), slot_data->num_loaded_partitions);
  EXPECT_EQ("boot",
            std::string(slot_data->loaded_partitions[0].partition_name));
  EXPECT_EQ(boot_part_size, slot_data->loaded_partitions[0].data_size);
  for (size_t n = 0; n < boot_part_size; n++) {
    EXPECT_EQ(uint8_t(n), slot_data->loaded_partitions[0].data[n]);
  }
  EXPECT_EQ("dtbo",
            std::string(slot_data->loaded_partitions[1].partition_name));
  EXPECT_EQ(dtbo_part_size, slot_data->loaded_partitions[1].data_size);
  for (size_t n = 0; n < dtbo_part_size; n++) {
    EXPECT_EQ(uint8_t(n + DTBO_DATA_OFFSET),
              slot_data->loaded_partitions[1].data[n]);
  }
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, VerificationDisabledUnmodified) {
  VerificationDisabled(false);  // use_avbctl
}

TEST_F(AvbSlotVerifyTest, VerificationDisabledModified) {
  VerificationDisabled(true);  // use_avbctl
}

// In the event that there's no vbmeta partition, we treat the vbmeta
// struct from 'boot' as the top-level partition. Check that this
// works.
TEST_F(AvbSlotVerifyTest, NoVBMetaPartition) {
  const size_t MiB = 1024 * 1024;
  const size_t boot_size = 6 * MiB;
  const size_t boot_part_size = 8 * MiB;
  const size_t system_size = 16 * MiB;
  const size_t system_part_size = 32 * MiB;
  const size_t foobar_size = 8 * MiB;
  const size_t foobar_part_size = 16 * MiB;
  const size_t bazboo_size = 4 * MiB;
  const size_t bazboo_part_size = 8 * MiB;
  base::FilePath boot_path = GenerateImage("boot.img", boot_size);
  base::FilePath system_path = GenerateImage("system.img", system_size);
  base::FilePath foobar_path = GenerateImage("foobar.img", foobar_size);
  base::FilePath bazboo_path = GenerateImage("bazboo.img", bazboo_size);

  EXPECT_COMMAND(0,
                 "./avbtool add_hashtree_footer --salt d00df00d --image %s "
                 "--partition_size %d --partition_name system "
                 "--algorithm SHA256_RSA2048 "
                 "--key test/data/testkey_rsa2048.pem "
                 "--internal_release_string \"\" "
                 "--do_not_generate_fec",
                 system_path.value().c_str(),
                 (int)system_part_size);

  EXPECT_COMMAND(0,
                 "./avbtool add_hashtree_footer --salt d00df00d --image %s "
                 "--partition_size %d --partition_name foobar "
                 "--algorithm SHA256_RSA2048 "
                 "--key test/data/testkey_rsa2048.pem "
                 "--internal_release_string \"\" "
                 "--do_not_generate_fec",
                 foobar_path.value().c_str(),
                 (int)foobar_part_size);

  EXPECT_COMMAND(0,
                 "./avbtool add_hashtree_footer --salt d00df00d --image %s "
                 "--partition_size %d --partition_name bazboo "
                 "--algorithm SHA512_RSA4096 "
                 "--key test/data/testkey_rsa4096.pem "
                 "--internal_release_string \"\" "
                 "--do_not_generate_fec",
                 bazboo_path.value().c_str(),
                 (int)bazboo_part_size);

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  // Explicitly pass "--flags 2147483648" (i.e. 1<<31) to check that
  // boot.img is treated as top-level. Note the corresponding "Flags:"
  // field below in the avbtool info_image output.
  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer --salt d00df00d "
                 "--hash_algorithm sha256 --image %s "
                 "--partition_size %d --partition_name boot "
                 "--algorithm SHA256_RSA2048 "
                 "--key test/data/testkey_rsa2048.pem "
                 "--internal_release_string \"\" "
                 "--include_descriptors_from_image %s "
                 "--include_descriptors_from_image %s "
                 "--setup_rootfs_from_kernel %s "
                 "--chain_partition bazboo:1:%s "
                 "--flags 2147483648",
                 boot_path.value().c_str(),
                 (int)boot_part_size,
                 system_path.value().c_str(),
                 foobar_path.value().c_str(),
                 system_path.value().c_str(),
                 pk_path.value().c_str());

  ASSERT_EQ(
      "Footer version:           1.0\n"
      "Image size:               8388608 bytes\n"
      "Original image size:      6291456 bytes\n"
      "VBMeta offset:            6291456\n"
      "VBMeta size:              3200 bytes\n"
      "--\n"
      "Minimum libavb version:   1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     320 bytes\n"
      "Auxiliary Block:          2624 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           0\n"
      "Flags:                    2147483648\n"
      "Release String:           ''\n"
      "Descriptors:\n"
      "    Hash descriptor:\n"
      "      Image Size:            6291456 bytes\n"
      "      Hash Algorithm:        sha256\n"
      "      Partition Name:        boot\n"
      "      Salt:                  d00df00d\n"
      "      Digest:                "
      "4c109399b20e476bab15363bff55740add83e1c1e97e0b132f5c713ddd8c7868\n"
      "    Chain Partition descriptor:\n"
      "      Partition Name:          bazboo\n"
      "      Rollback Index Location: 1\n"
      "      Public key (sha1):       "
      "2597c218aae470a130f61162feaae70afd97f011\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 1\n"
      "      Kernel Cmdline:        'dm=\"1 vroot none ro 1,0 32768 verity 1 "
      "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) PARTUUID=$(ANDROID_SYSTEM_PARTUUID) "
      "4096 4096 4096 4096 sha1 c9ffc3bfae5000269a55a56621547fd1fcf819df "
      "d00df00d 2 $(ANDROID_VERITY_MODE) ignore_zero_blocks\" root=/dev/dm-0'\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 2\n"
      "      Kernel Cmdline:        "
      "'root=PARTUUID=$(ANDROID_SYSTEM_PARTUUID)'\n"
      "    Hashtree descriptor:\n"
      "      Version of dm-verity:  1\n"
      "      Image Size:            16777216 bytes\n"
      "      Tree Offset:           16777216\n"
      "      Tree Size:             135168 bytes\n"
      "      Data Block Size:       4096 bytes\n"
      "      Hash Block Size:       4096 bytes\n"
      "      FEC num roots:         0\n"
      "      FEC offset:            0\n"
      "      FEC size:              0 bytes\n"
      "      Hash Algorithm:        sha1\n"
      "      Partition Name:        system\n"
      "      Salt:                  d00df00d\n"
      "      Root Digest:           c9ffc3bfae5000269a55a56621547fd1fcf819df\n"
      "    Hashtree descriptor:\n"
      "      Version of dm-verity:  1\n"
      "      Image Size:            8388608 bytes\n"
      "      Tree Offset:           8388608\n"
      "      Tree Size:             69632 bytes\n"
      "      Data Block Size:       4096 bytes\n"
      "      Hash Block Size:       4096 bytes\n"
      "      FEC num roots:         0\n"
      "      FEC offset:            0\n"
      "      FEC size:              0 bytes\n"
      "      Hash Algorithm:        sha1\n"
      "      Partition Name:        foobar\n"
      "      Salt:                  d00df00d\n"
      "      Root Digest:           d52d93c988d336a79abe1c05240ae9a79a9b7d61\n",
      InfoImage(boot_path));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  // Now check that libavb will fall back to reading from 'boot'
  // instead of 'vbmeta' when encountering
  // AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION on trying to read from
  // 'vbmeta'.
  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  // Note 'boot' in the value androidboot.vbmeta.device since we've
  // read from 'boot' and not 'vbmeta'.
  EXPECT_EQ(
      "dm=\"1 vroot none ro 1,0 32768 verity 1 "
      "PARTUUID=1234-fake-guid-for:system PARTUUID=1234-fake-guid-for:system "
      "4096 4096 4096 4096 sha1 c9ffc3bfae5000269a55a56621547fd1fcf819df "
      "d00df00d 2 restart_on_corruption ignore_zero_blocks\" root=/dev/dm-0 "
      "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:boot "
      "androidboot.vbmeta.avb_version=1.0 "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=5312 "
      "androidboot.vbmeta.digest="
      "6b06719a940e5d8fa53ffef91eb4f0517ff0dda9833b90be1c9624ab3a5261d2 "
      "androidboot.vbmeta.invalidate_on_error=yes "
      "androidboot.veritymode=enforcing",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);
}

// Check that non-zero flags in chained partition are caught in
// avb_slot_verify().
TEST_F(AvbSlotVerifyTest, ChainedPartitionEnforceFlagsZero) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  const size_t boot_image_size = 5 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", boot_image_size);
  const char* requested_partitions[] = {"boot", NULL};

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --kernel_cmdline 'cmdline2 in hash footer'"
                 " --rollback_index 12"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --algorithm SHA256_RSA4096"
                 " --key test/data/testkey_rsa4096.pem"
                 " --salt deadbeef"
                 " --flags 1"
                 " --internal_release_string \"\"",
                 boot_path.value().c_str(),
                 boot_partition_size);

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  GenerateVBMetaImage(
      "vbmeta_a.img",
      "SHA256_RSA2048",
      11,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf("--chain_partition boot:1:%s"
                         " --kernel_cmdline 'cmdline2 in vbmeta'"
                         " --internal_release_string \"\"",
                         pk_path.value().c_str()));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
}

// Check that chain descriptors in chained partitions are caught in
// avb_slot_verify().
TEST_F(AvbSlotVerifyTest, ChainedPartitionEnforceNoChainPartitions) {
  size_t boot_partition_size = 16 * 1024 * 1024;
  const size_t boot_image_size = 5 * 1024 * 1024;
  base::FilePath boot_path = GenerateImage("boot_a.img", boot_image_size);
  const char* requested_partitions[] = {"boot", NULL};

  base::FilePath pk_path = testdir_.Append("testkey_rsa4096.avbpubkey");
  EXPECT_COMMAND(
      0,
      "./avbtool extract_public_key --key test/data/testkey_rsa4096.pem"
      " --output %s",
      pk_path.value().c_str());

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --kernel_cmdline 'cmdline2 in hash footer'"
                 " --rollback_index 12"
                 " --partition_name boot"
                 " --partition_size %zd"
                 " --algorithm SHA256_RSA4096"
                 " --key test/data/testkey_rsa4096.pem"
                 " --salt deadbeef"
                 " --chain_partition other:2:%s"
                 " --internal_release_string \"\"",
                 boot_path.value().c_str(),
                 boot_partition_size,
                 pk_path.value().c_str());

  GenerateVBMetaImage(
      "vbmeta_a.img",
      "SHA256_RSA2048",
      11,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf("--chain_partition boot:1:%s"
                         " --kernel_cmdline 'cmdline2 in vbmeta'"
                         " --internal_release_string \"\"",
                         pk_path.value().c_str()));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "_a",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
}

TEST_F(AvbSlotVerifyTest, HashtreeErrorModes) {
  const size_t MiB = 1024 * 1024;
  const size_t system_size = 16 * MiB;
  const size_t system_part_size = 32 * MiB;
  base::FilePath system_path = GenerateImage("system.img", system_size);

  EXPECT_COMMAND(0,
                 "./avbtool add_hashtree_footer --salt d00df00d --image %s "
                 "--partition_size %d --partition_name system "
                 "--algorithm SHA256_RSA2048 "
                 "--key test/data/testkey_rsa2048.pem "
                 "--internal_release_string \"\" "
                 "--do_not_generate_fec",
                 system_path.value().c_str(),
                 (int)system_part_size);

  GenerateVBMetaImage("vbmeta.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--setup_rootfs_from_kernel %s "
                                         "--include_descriptors_from_image %s"
                                         " --internal_release_string \"\"",
                                         system_path.value().c_str(),
                                         system_path.value().c_str()));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};

  // For AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE we should get
  // androidboot.vbmeta.invalidate_on_error=yes and
  // androidboot.veritymode=enforcing. We should get
  // 'restart_on_corruption' in the dm="..." string.
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "dm=\"1 vroot none ro 1,0 32768 verity 1 "
      "PARTUUID=1234-fake-guid-for:system "
      "PARTUUID=1234-fake-guid-for:system 4096 4096 4096 4096 sha1 "
      "c9ffc3bfae5000269a55a56621547fd1fcf819df d00df00d 2 "
      "restart_on_corruption ignore_zero_blocks\" root=/dev/dm-0 "
      "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
      "androidboot.vbmeta.avb_version=1.0 "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 "
      "androidboot.vbmeta.size=1664 "
      "androidboot.vbmeta.digest="
      "e6c8c7d819f6b05ec0ebf7f73ee3b09f8d395e70ee040fe34f8fa6bccc8df798 "
      "androidboot.vbmeta.invalidate_on_error=yes "
      "androidboot.veritymode=enforcing",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);

  // For AVB_HASHTREE_ERROR_MODE_RESTART we should get
  // androidboot.veritymode=enforcing and
  // androidboot.vbmeta.invalidate_on_error should be unset. We should
  // get 'restart_on_corruption' in the dm="..." string.
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_RESTART,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "dm=\"1 vroot none ro 1,0 32768 verity 1 "
      "PARTUUID=1234-fake-guid-for:system "
      "PARTUUID=1234-fake-guid-for:system 4096 4096 4096 4096 sha1 "
      "c9ffc3bfae5000269a55a56621547fd1fcf819df d00df00d 2 "
      "restart_on_corruption ignore_zero_blocks\" root=/dev/dm-0 "
      "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
      "androidboot.vbmeta.avb_version=1.0 "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 "
      "androidboot.vbmeta.size=1664 "
      "androidboot.vbmeta.digest="
      "e6c8c7d819f6b05ec0ebf7f73ee3b09f8d395e70ee040fe34f8fa6bccc8df798 "
      "androidboot.veritymode=enforcing",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);

  // For AVB_HASHTREE_ERROR_MODE_EIO we should get
  // androidboot.veritymode=eio and
  // androidboot.vbmeta.invalidate_on_error should be unset. We should
  // get 'ignore_zero_blocks' in the dm="..." string.
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_EIO,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "dm=\"1 vroot none ro 1,0 32768 verity 1 "
      "PARTUUID=1234-fake-guid-for:system "
      "PARTUUID=1234-fake-guid-for:system 4096 4096 4096 4096 sha1 "
      "c9ffc3bfae5000269a55a56621547fd1fcf819df d00df00d 2 "
      "ignore_zero_blocks ignore_zero_blocks\" root=/dev/dm-0 "
      "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
      "androidboot.vbmeta.avb_version=1.0 "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 "
      "androidboot.vbmeta.size=1664 "
      "androidboot.vbmeta.digest="
      "e6c8c7d819f6b05ec0ebf7f73ee3b09f8d395e70ee040fe34f8fa6bccc8df798 "
      "androidboot.veritymode=eio",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);

  // For AVB_HASHTREE_ERROR_MODE_LOGGING we should get
  // androidboot.veritymode=logging and
  // androidboot.vbmeta.invalidate_on_error should be unset. We should
  // get 'ignore_corruption' in the dm="..." string.
  //
  // Check AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT is returned
  // unless we pass AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR.
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_ARGUMENT,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "",
                            AVB_SLOT_VERIFY_FLAGS_NONE,
                            AVB_HASHTREE_ERROR_MODE_LOGGING,
                            &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  // --
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(),
                            requested_partitions,
                            "",
                            AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                            AVB_HASHTREE_ERROR_MODE_LOGGING,
                            &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "dm=\"1 vroot none ro 1,0 32768 verity 1 "
      "PARTUUID=1234-fake-guid-for:system "
      "PARTUUID=1234-fake-guid-for:system 4096 4096 4096 4096 sha1 "
      "c9ffc3bfae5000269a55a56621547fd1fcf819df d00df00d 2 "
      "ignore_corruption ignore_zero_blocks\" root=/dev/dm-0 "
      "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
      "androidboot.vbmeta.avb_version=1.0 "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 "
      "androidboot.vbmeta.size=1664 "
      "androidboot.vbmeta.digest="
      "e6c8c7d819f6b05ec0ebf7f73ee3b09f8d395e70ee040fe34f8fa6bccc8df798 "
      "androidboot.veritymode=logging",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);

  // Check we'll get androidboot.veritymode=disabled for any
  // |hashtree_error_mode| if dm-verity is disabled.
  GenerateVBMetaImage("vbmeta.img",
                      "SHA256_RSA2048",
                      0,
                      base::FilePath("test/data/testkey_rsa2048.pem"),
                      base::StringPrintf("--setup_rootfs_from_kernel %s "
                                         "--include_descriptors_from_image %s "
                                         "--set_hashtree_disabled_flag "
                                         "--internal_release_string \"\"",
                                         system_path.value().c_str(),
                                         system_path.value().c_str()));
  for (int n = 0; n < 4; n++) {
    AvbHashtreeErrorMode modes[4] = {
        AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
        AVB_HASHTREE_ERROR_MODE_RESTART,
        AVB_HASHTREE_ERROR_MODE_EIO,
        AVB_HASHTREE_ERROR_MODE_LOGGING};
    EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
              avb_slot_verify(ops_.avb_ops(),
                              requested_partitions,
                              "",
                              AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
                              modes[n],
                              &slot_data));
    EXPECT_NE(nullptr, slot_data);
    EXPECT_EQ(
        "root=PARTUUID=1234-fake-guid-for:system "
        "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta "
        "androidboot.vbmeta.avb_version=1.0 "
        "androidboot.vbmeta.device_state=locked "
        "androidboot.vbmeta.hash_alg=sha256 "
        "androidboot.vbmeta.size=1664 "
        "androidboot.vbmeta.digest="
        "e73a466d63f451dcf5c051ff12a32c006ba282a34b37420c0d563f0282cad703 "
        "androidboot.veritymode=disabled",
        std::string(slot_data->cmdline));
    avb_slot_verify_data_free(slot_data);
  }
}

}  // namespace avb
