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

class AvbSlotVerifyTest : public BaseAvbToolTest {
 public:
  AvbSlotVerifyTest() {}

  virtual void SetUp() override {
    BaseAvbToolTest::SetUp();
    ops_.set_partition_dir(testdir_);
    ops_.set_stored_rollback_indexes({0, 0, 0, 0});
    ops_.set_stored_is_device_unlocked(false);
  }

  void CmdlineWithHashtreeVerification(bool hashtree_verification_on);

  FakeAvbOps ops_;
};

TEST_F(AvbSlotVerifyTest, Basic) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "androidboot.slot_suffix=_a androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1408 "
      "androidboot.vbmeta.digest="
      "812d4f9c27f3ae1b3d1448f276b519b85eed0a35af69656b9fd14ec72986af0a",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, BasicSha512) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA512_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "androidboot.slot_suffix=_a androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha512 androidboot.vbmeta.size=1472 "
      "androidboot.vbmeta.digest="
      "9bfb82f10fd5436c2f1739a7a2c71f441aa3349aa76a219d1978705092a7d791b291908b"
      "7b85ac6818fa5bcbdefdf1c3af6b1e56b0a5b9faff73d359258fc4dd",
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
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "androidboot.slot_suffix=_a androidboot.vbmeta.device_state=unlocked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1408 "
      "androidboot.vbmeta.digest="
      "812d4f9c27f3ae1b3d1448f276b519b85eed0a35af69656b9fd14ec72986af0a",
      std::string(slot_data->cmdline));
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, SlotDataIsCorrect) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, WrongPublicKey) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            true /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, NoImage) {
  const char* requested_partitions[] = {"boot", NULL};
  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_IO,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_EQ(nullptr, slot_data);
}

TEST_F(AvbSlotVerifyTest, UnsignedVBMeta) {
  GenerateVBMetaImage("vbmeta_a.img", "", 0, base::FilePath(""));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            true /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
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

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            true /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);
}

TEST_F(AvbSlotVerifyTest, CorruptedMetadata) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 0,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  // Corrupt four bytes of data in the beginning of the image. Unlike
  // the CorruptedImage test-case above (which is valid metadata) this
  // will make the metadata invalid and render the slot unbootable
  // even if the device is unlocked. Specifically no AvbSlotVerifyData
  // is returned.
  uint8_t corrupt_data[4] = {0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(AVB_IO_RESULT_OK, ops_.avb_ops()->write_to_partition(
                                  ops_.avb_ops(), "vbmeta_a",
                                  0,  // offset: beginning
                                  sizeof corrupt_data, corrupt_data));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_INVALID_METADATA,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_EQ(nullptr, slot_data);
}

TEST_F(AvbSlotVerifyTest, RollbackIndex) {
  GenerateVBMetaImage("vbmeta_a.img", "SHA256_RSA2048", 42,
                      base::FilePath("test/data/testkey_rsa2048.pem"));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};

  // First try with 42 as the stored rollback index - this should
  // succeed since the image rollback index is 42 (as set above).
  ops_.set_stored_rollback_indexes({42});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);

  // Then try with 43 for the stored rollback index - this should fail
  // because the image has rollback index 42 which is less than 43.
  ops_.set_stored_rollback_indexes({43});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            true /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
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
      "Auxiliary Block:          896 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           4\n"
      "Flags:                    0\n"
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
  EXPECT_COMMAND(1, "./avbtool info_image --image %s",
                 boot_path.value().c_str());

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);

  // Now verify the slot data. The vbmeta data should match our
  // vbmeta_image_ member.
  EXPECT_EQ(slot_data->vbmeta_size, vbmeta_image_.size());
  EXPECT_EQ(0, memcmp(vbmeta_image_.data(), slot_data->vbmeta_data,
                      slot_data->vbmeta_size));

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
      "cmdline in vbmeta 1234-fake-guid-for:boot_a "
      "cmdline in hash footer 1234-fake-guid-for:system_a "
      "androidboot.slot_suffix=_a "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1728 "
      "androidboot.vbmeta.digest="
      "aca82b8c227721a389e89643c7e8ced39b3c587337bc9c10539c09a50026121f",
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
  const char* requested_partitions[] = {"boot", NULL};

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
  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);

  // Now corrupt boot_a.img and expect verification error.
  uint8_t corrupt_data[4] = {0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(AVB_IO_RESULT_OK, ops_.avb_ops()->write_to_partition(
                                  ops_.avb_ops(), "boot_a",
                                  1024 * 1024,  // offset: 1 MiB
                                  sizeof corrupt_data, corrupt_data));

  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            true /* allow_verification_error */, &slot_data));
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
      "Auxiliary Block:          1728 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           11\n"
      "Flags:                    0\n"
      "Descriptors:\n"
      "    Chain Partition descriptor:\n"
      "      Partition Name:        boot\n"
      "      Rollback Index Slot:   1\n"
      "      Public key (sha1):     2597c218aae470a130f61162feaae70afd97f011\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 0\n"
      "      Kernel Cmdline:        'cmdline2 in vbmeta'\n",
      InfoImage(vbmeta_image_path_));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);

  // Now verify the slot data. The vbmeta data should match our
  // vbmeta_image_ member.
  EXPECT_EQ(slot_data->vbmeta_size, vbmeta_image_.size());
  EXPECT_EQ(0, memcmp(vbmeta_image_.data(), slot_data->vbmeta_data,
                      slot_data->vbmeta_size));

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
      "androidboot.slot_suffix=_a "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=2560 "
      "androidboot.vbmeta.digest="
      "885bd66f0d8e95631ecd5052ca34323cdc69948b370a45b671a2d7e164c36972",
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
  const char* requested_partitions[] = {"boot", NULL};

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

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);

  // Now corrupt boot_a.img and expect verification error.
  uint8_t corrupt_data[4] = {0xff, 0xff, 0xff, 0xff};
  EXPECT_EQ(AVB_IO_RESULT_OK, ops_.avb_ops()->write_to_partition(
                                  ops_.avb_ops(), "boot_a",
                                  1024 * 1024,  // offset: 1 MiB
                                  sizeof corrupt_data, corrupt_data));

  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            true /* allow_verification_error */, &slot_data));
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

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            true /* allow_verification_error */, &slot_data));
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

  AvbSlotVerifyData* slot_data = NULL;

  // Both images (vbmeta_a and boot_a) have rollback index 10 and 11
  // so it should work if the stored rollback indexes are 0 and 0.
  ops_.set_stored_rollback_indexes({0, 0});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);

  // Check failure if we set the stored rollback index of the chained
  // partition to 20 (see AvbSlotVerifyTest.RollbackIndex above
  // where we test rollback index checks for the vbmeta partition).
  ops_.set_stored_rollback_indexes({0, 20});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_EQ(nullptr, slot_data);
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            true /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  avb_slot_verify_data_free(slot_data);

  // Check failure if there is no rollback index slot 1 - in that case
  // we expect an I/O error since ops->read_rollback_index() will
  // fail.
  ops_.set_stored_rollback_indexes({0});
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_ERROR_IO,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
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
      "Auxiliary Block:          1728 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           11\n"
      "Flags:                    0\n"
      "Descriptors:\n"
      "    Chain Partition descriptor:\n"
      "      Partition Name:        boot\n"
      "      Rollback Index Slot:   1\n"
      "      Public key (sha1):     2597c218aae470a130f61162feaae70afd97f011\n"
      "    Kernel Cmdline descriptor:\n"
      "      Flags:                 0\n"
      "      Kernel Cmdline:        'cmdline2 in vbmeta'\n",
      InfoImage(vbmeta_image_path_));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  AvbSlotVerifyData* slot_data = NULL;
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);

  // Now verify the slot data. The vbmeta data should match our
  // vbmeta_image_ member.
  EXPECT_EQ(slot_data->vbmeta_size, vbmeta_image_.size());
  EXPECT_EQ(0, memcmp(vbmeta_image_.data(), slot_data->vbmeta_data,
                      slot_data->vbmeta_size));

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
  // them - note that androidboot.slot_suffix is not set since we
  // don't have any slots in this setup.
  EXPECT_EQ(
      "cmdline2 in hash footer cmdline2 in vbmeta "
      "androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=2560 "
      "androidboot.vbmeta.digest="
      "885bd66f0d8e95631ecd5052ca34323cdc69948b370a45b671a2d7e164c36972",
      std::string(slot_data->cmdline));
  EXPECT_EQ(11UL, slot_data->rollback_indexes[0]);
  EXPECT_EQ(12UL, slot_data->rollback_indexes[1]);
  for (size_t n = 2; n < AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_SLOTS; n++) {
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
                 " --salt deadbeef",
                 foo_path.value().c_str(), foo_partition_size);

  EXPECT_COMMAND(0,
                 "./avbtool add_hash_footer"
                 " --image %s"
                 " --partition_name bar"
                 " --partition_size %zd"
                 " --salt deadbeef",
                 bar_path.value().c_str(), bar_partition_size);

  GenerateVBMetaImage(
      "vbmeta_a.img", "SHA256_RSA2048", 4,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf("--include_descriptors_from_image %s"
                         " --include_descriptors_from_image %s",
                         foo_path.value().c_str(), bar_path.value().c_str()));

  EXPECT_EQ(
      "VBMeta image version:     1.0\n"
      "Header Block:             256 bytes\n"
      "Authentication Block:     576 bytes\n"
      "Auxiliary Block:          896 bytes\n"
      "Algorithm:                SHA256_RSA2048\n"
      "Rollback Index:           4\n"
      "Flags:                    0\n"
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
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);

  // Now verify the slot data. The vbmeta data should match our
  // vbmeta_image_ member.
  EXPECT_EQ(slot_data->vbmeta_size, vbmeta_image_.size());
  EXPECT_EQ(0, memcmp(vbmeta_image_.data(), slot_data->vbmeta_data,
                      slot_data->vbmeta_size));

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
}

TEST_F(AvbSlotVerifyTest, PublicKeyMetadata) {
  base::FilePath md_path = GenerateImage("md.bin", 1536);

  GenerateVBMetaImage(
      "vbmeta_a.img", "SHA256_RSA2048", 0,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf("--public_key_metadata %s", md_path.value().c_str()));

  ops_.set_expected_public_key(
      PublicKeyAVB(base::FilePath("test/data/testkey_rsa2048.pem")));

  std::string md_data;
  ASSERT_TRUE(base::ReadFileToString(md_path, &md_data));
  ops_.set_expected_public_key_metadata(md_data);

  AvbSlotVerifyData* slot_data = NULL;
  const char* requested_partitions[] = {"boot", NULL};
  EXPECT_EQ(AVB_SLOT_VERIFY_RESULT_OK,
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  EXPECT_EQ(
      "androidboot.slot_suffix=_a androidboot.vbmeta.device_state=locked "
      "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=2944 "
      "androidboot.vbmeta.digest="
      "eb65f3384a8e37b164743d35f70c527769f4a2152f5129151a7987d5d82efa6d",
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
  for (size_t n = 0; n < rootfs_size; n++) rootfs[n] = uint8_t(n);
  base::FilePath rootfs_path = testdir_.Append("rootfs.bin");
  EXPECT_EQ(rootfs_size,
            static_cast<const size_t>(base::WriteFile(
                rootfs_path, reinterpret_cast<const char*>(rootfs.data()),
                rootfs.size())));

  EXPECT_COMMAND(0,
                 "./avbtool add_hashtree_footer --salt d00df00d --image %s "
                 "--partition_size %d --partition_name foobar "
                 "--algorithm SHA256_RSA2048 "
                 "--key test/data/testkey_rsa2048.pem",
                 rootfs_path.value().c_str(), (int)partition_size);

  // Check that we correctly generate dm-verity kernel cmdline
  // snippets, if requested.
  GenerateVBMetaImage(
      "vbmeta_a.img", "SHA256_RSA2048", 4,
      base::FilePath("test/data/testkey_rsa2048.pem"),
      base::StringPrintf("--generate_dm_verity_cmdline_from_hashtree %s "
                         "--kernel_cmdline should_be_in_both=1 "
                         "--algorithm SHA256_RSA2048 "
                         "--flags %d ",
                         rootfs_path.value().c_str(),
                         hashtree_verification_on
                             ? 0
                             : AVB_VBMETA_IMAGE_FLAGS_HASHTREE_DISABLED));

  EXPECT_EQ(
      base::StringPrintf(
          "VBMeta image version:     1.0\n"
          "Header Block:             256 bytes\n"
          "Authentication Block:     576 bytes\n"
          "Auxiliary Block:          960 bytes\n"
          "Algorithm:                SHA256_RSA2048\n"
          "Rollback Index:           4\n"
          "Flags:                    %d\n"
          "Descriptors:\n"
          "    Kernel Cmdline descriptor:\n"
          "      Flags:                 1\n"
          "      Kernel Cmdline:        'dm=\"1 vroot none ro 1,0 2056 verity "
          "1 PARTUUID=$(ANDROID_SYSTEM_PARTUUID) "
          "PARTUUID=$(ANDROID_SYSTEM_PARTUUID) 4096 4096 257 257 sha1 "
          "e811611467dcd6e8dc4324e45f706c2bdd51db67 d00df00d 1 "
          "ignore_zero_blocks\" root=0xfd00 "
          "androidboot.vbmeta.device=PARTUUID=$(ANDROID_VBMETA_PARTUUID)'\n"
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
            avb_slot_verify(ops_.avb_ops(), requested_partitions, "_a",
                            false /* allow_verification_error */, &slot_data));
  EXPECT_NE(nullptr, slot_data);
  if (hashtree_verification_on) {
    EXPECT_EQ(
        "dm=\"1 vroot none ro 1,0 2056 verity 1 "
        "PARTUUID=1234-fake-guid-for:system_a "
        "PARTUUID=1234-fake-guid-for:system_a 4096 4096 257 257 sha1 "
        "e811611467dcd6e8dc4324e45f706c2bdd51db67 d00df00d 1 "
        "ignore_zero_blocks\" root=0xfd00 "
        "androidboot.vbmeta.device=PARTUUID=1234-fake-guid-for:vbmeta_a "
        "should_be_in_both=1 androidboot.slot_suffix=_a "
        "androidboot.vbmeta.device_state=locked "
        "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1792 "
        "androidboot.vbmeta.digest="
        "597b8c9dafbd0e01952e23b72dd805269a46302000582f6ebc5ebbb998378871",
        std::string(slot_data->cmdline));
  } else {
    EXPECT_EQ(
        "root=PARTUUID=1234-fake-guid-for:system_a should_be_in_both=1 "
        "androidboot.slot_suffix=_a androidboot.vbmeta.device_state=locked "
        "androidboot.vbmeta.hash_alg=sha256 androidboot.vbmeta.size=1792 "
        "androidboot.vbmeta.digest="
        "b574b9765f17fc98a90dda0f1e277bacbbd5f01c1e9a3c9a507252085df8a580",
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
