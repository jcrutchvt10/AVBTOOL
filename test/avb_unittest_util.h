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

#ifndef AVB_UNITTEST_UTIL_H_
#define AVB_UNITTEST_UTIL_H_

#include <inttypes.h>

#include <gtest/gtest.h>

#include <base/files/file_util.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

/* Utility macro to run the command expressed by the printf()-style string
 * |command_format| using the system(3) utility function. Will assert unless
 * the command exits normally with exit status |expected_exit_status|.
 */
#define EXPECT_COMMAND(expected_exit_status, command_format, ...)          \
  do {                                                                     \
    int rc =                                                               \
        system(base::StringPrintf(command_format, ##__VA_ARGS__).c_str()); \
    EXPECT_TRUE(WIFEXITED(rc));                                            \
    EXPECT_EQ(WEXITSTATUS(rc), expected_exit_status);                      \
  } while (0);

/* Base-class used for unit test. */
class BaseAvbToolTest : public ::testing::Test {
 public:
  BaseAvbToolTest() {}

 protected:
  virtual ~BaseAvbToolTest() {}

  /* Generates a Brillo vbmeta image, using avbtoool, with file name
   * |image_name|. The generated vbmeta image will written to disk,
   * see the |vbmeta_image_path_| variable for its path and
   * |vbmeta_image_| for the content.
   */
  void GenerateVBMetaImage(const std::string& image_name,
                           const std::string& algorithm,
                           uint64_t rollback_index,
                           const base::FilePath& key_path,
                           const std::string& additional_options = "") {
    std::string signing_options;
    if (algorithm == "") {
      signing_options = " --algorithm NONE ";
    } else {
      signing_options = std::string(" --algorithm ") + algorithm + " --key " +
                        key_path.value() + " ";
    }
    vbmeta_image_path_ = testdir_.Append(image_name);
    EXPECT_COMMAND(0,
                   "./avbtool make_vbmeta_image"
                   " --rollback_index %" PRIu64
                   " %s %s "
                   " --output %s",
                   rollback_index, additional_options.c_str(),
                   signing_options.c_str(), vbmeta_image_path_.value().c_str());
    int64_t file_size;
    ASSERT_TRUE(base::GetFileSize(vbmeta_image_path_, &file_size));
    vbmeta_image_.resize(file_size);
    ASSERT_TRUE(base::ReadFile(vbmeta_image_path_,
                               reinterpret_cast<char*>(vbmeta_image_.data()),
                               vbmeta_image_.size()));
  }

  /* Returns the output of 'avbtool info_image' for a given image. */
  std::string InfoImage(const base::FilePath& image_path) {
    base::FilePath tmp_path = testdir_.Append("info_output.txt");
    EXPECT_COMMAND(0, "./avbtool info_image --image %s --output %s",
                   image_path.value().c_str(), tmp_path.value().c_str());
    std::string info_data;
    EXPECT_TRUE(base::ReadFileToString(tmp_path, &info_data));
    return info_data;
  }

  /* Returns public key in AVB format for a .pem key */
  std::string PublicKeyAVB(const base::FilePath& key_path) {
    base::FilePath tmp_path = testdir_.Append("public_key.bin");
    EXPECT_COMMAND(0,
                   "./avbtool extract_public_key --key %s"
                   " --output %s",
                   key_path.value().c_str(), tmp_path.value().c_str());
    std::string key_data;
    EXPECT_TRUE(base::ReadFileToString(tmp_path, &key_data));
    return key_data;
  }

  /* Create temporary directory to stash images in. */
  virtual void SetUp() override {
    base::FilePath ret;
    char* buf = strdup("/tmp/libavb-tests.XXXXXX");
    ASSERT_TRUE(mkdtemp(buf) != nullptr);
    testdir_ = base::FilePath(buf);
    free(buf);
  }

  /* Nuke temporary directory. */
  virtual void TearDown() override {
    ASSERT_EQ(0U, testdir_.value().find("/tmp/libavb-tests"));
    ASSERT_TRUE(base::DeleteFile(testdir_, true /* recursive */));
  }

  /* Temporary directory created in SetUp(). */
  base::FilePath testdir_;

  /* Path to vbmeta image generated with GenerateVBMetaImage(). */
  base::FilePath vbmeta_image_path_;

  /* Contents of the image generated with GenerateVBMetaImage(). */
  std::vector<uint8_t> vbmeta_image_;
};

#endif /* AVB_UNITTEST_UTIL_H_ */
