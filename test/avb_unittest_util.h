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

#ifndef AVB_UNITTEST_UTIL_H_
#define AVB_UNITTEST_UTIL_H_

#include <inttypes.h>

#include <gtest/gtest.h>

#include <base/files/file_util.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

// Encodes |len| bytes of |data| as a lower-case hex-string.
std::string mem_to_hexstring(const uint8_t* data, size_t len);

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

namespace avb {

// These two functions are in avb_sysdeps_posix_testing.cc and is
// used for finding memory leaks.
void testing_memory_reset();
size_t testing_memory_all_freed();

/* Base-class used for unit test. */
class BaseAvbToolTest : public ::testing::Test {
 public:
  BaseAvbToolTest() {}

 protected:
  virtual ~BaseAvbToolTest() {}

  /* Generates a vbmeta image, using avbtoool, with file name
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
                   rollback_index,
                   additional_options.c_str(),
                   signing_options.c_str(),
                   vbmeta_image_path_.value().c_str());
    int64_t file_size;
    ASSERT_TRUE(base::GetFileSize(vbmeta_image_path_, &file_size));
    vbmeta_image_.resize(file_size);
    ASSERT_TRUE(base::ReadFile(vbmeta_image_path_,
                               reinterpret_cast<char*>(vbmeta_image_.data()),
                               vbmeta_image_.size()));
  }

  /* Generate a file with name |file_name| of size |image_size| with
   * known content (0x00 0x01 0x02 .. 0xff 0x00 0x01 ..).
   */
  base::FilePath GenerateImage(const std::string file_name, size_t image_size) {
    std::vector<uint8_t> image;
    image.resize(image_size);
    for (size_t n = 0; n < image_size; n++) {
      image[n] = uint8_t(n);
    }
    base::FilePath image_path = testdir_.Append(file_name);
    EXPECT_EQ(image_size,
              static_cast<const size_t>(
                  base::WriteFile(image_path,
                                  reinterpret_cast<const char*>(image.data()),
                                  image.size())));
    return image_path;
  }

  /* Returns the output of 'avbtool info_image' for a given image. */
  std::string InfoImage(const base::FilePath& image_path) {
    base::FilePath tmp_path = testdir_.Append("info_output.txt");
    EXPECT_COMMAND(0,
                   "./avbtool info_image --image %s --output %s",
                   image_path.value().c_str(),
                   tmp_path.value().c_str());
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
                   key_path.value().c_str(),
                   tmp_path.value().c_str());
    std::string key_data;
    EXPECT_TRUE(base::ReadFileToString(tmp_path, &key_data));
    return key_data;
  }

  virtual void SetUp() override {
    /* Create temporary directory to stash images in. */
    base::FilePath ret;
    char* buf = strdup("/tmp/libavb-tests.XXXXXX");
    ASSERT_TRUE(mkdtemp(buf) != nullptr);
    testdir_ = base::FilePath(buf);
    free(buf);
    /* Reset memory leak tracing */
    avb::testing_memory_reset();
  }

  virtual void TearDown() override {
    /* Nuke temporary directory. */
    ASSERT_EQ(0U, testdir_.value().find("/tmp/libavb-tests"));
    ASSERT_TRUE(base::DeleteFile(testdir_, true /* recursive */));
    /* Ensure all memory has been freed. */
    EXPECT_TRUE(avb::testing_memory_all_freed());
  }

  /* Temporary directory created in SetUp(). */
  base::FilePath testdir_;

  /* Path to vbmeta image generated with GenerateVBMetaImage(). */
  base::FilePath vbmeta_image_path_;

  /* Contents of the image generated with GenerateVBMetaImage(). */
  std::vector<uint8_t> vbmeta_image_;
};

}  // namespace avb

#endif /* AVB_UNITTEST_UTIL_H_ */
