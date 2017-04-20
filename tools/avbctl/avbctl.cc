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

#include <android-base/properties.h>

#include <libavb_user/libavb_user.h>

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
          "  %s get-verity        - Prints whether verity is enabled in "
          "current slot.\n"
          "  %s disable-verity    - Disable verity in current slot.\n"
          "  %s enable-verity     - Enable verity in current slot.\n",
          argv[0],
          argv[0],
          argv[0],
          argv[0],
          argv[0]);
}

/* Function to enable and disable dm-verity. The |ops| parameter
 * should be an |AvbOps| from libavb_user.
 */
int do_set_verity(AvbOps* ops,
                  const std::string& ab_suffix,
                  bool enable_verity) {
  bool verity_enabled;

  if (!avb_user_verity_get(ops, ab_suffix.c_str(), &verity_enabled)) {
    fprintf(stderr, "Error getting whether verity is enabled.\n");
    return EX_SOFTWARE;
  }

  if ((verity_enabled && enable_verity) ||
      (!verity_enabled && !enable_verity)) {
    fprintf(stdout,
            "verity is already %s",
            verity_enabled ? "enabled" : "disabled");
    if (ab_suffix != "") {
      fprintf(stdout, " on slot with suffix %s", ab_suffix.c_str());
    }
    fprintf(stdout, ".\n");
    return EX_OK;
  }

  if (!avb_user_verity_set(ops, ab_suffix.c_str(), enable_verity)) {
    fprintf(stderr, "Error setting verity.\n");
    return EX_SOFTWARE;
  }

  fprintf(
      stdout, "Successfully %s verity", enable_verity ? "enabled" : "disabled");
  if (ab_suffix != "") {
    fprintf(stdout, " on slot with suffix %s", ab_suffix.c_str());
  }
  fprintf(stdout, ". Reboot the device for changes to take effect.\n");

  return EX_OK;
}

/* Function to query if dm-verity is enabled. The |ops| parameter
 * should be an |AvbOps| from libavb_user.
 */
int do_get_verity(AvbOps* ops, const std::string& ab_suffix) {
  bool verity_enabled;

  if (!avb_user_verity_get(ops, ab_suffix.c_str(), &verity_enabled)) {
    fprintf(stderr, "Error getting whether verity is enabled.\n");
    return EX_SOFTWARE;
  }

  fprintf(stdout, "verity is %s", verity_enabled ? "enabled" : "disabled");
  if (ab_suffix != "") {
    fprintf(stdout, " on slot with suffix %s", ab_suffix.c_str());
  }
  fprintf(stdout, ".\n");

  return EX_OK;
}

/* Helper function to get A/B suffix, if any. If the device isn't
 * using A/B the empty string is returned. Otherwise either "_a",
 * "_b", ... is returned.
 *
 * Note that since sometime in O androidboot.slot_suffix is deprecated
 * and androidboot.slot should be used instead. Since bootloaders may
 * be out of sync with the OS, we check both and for extra safety
 * prepend a leading underscore if there isn't one already.
 */
std::string get_ab_suffix() {
  std::string ab_suffix = android::base::GetProperty("ro.boot.slot_suffix", "");
  if (ab_suffix == "") {
    ab_suffix = android::base::GetProperty("ro.boot.slot", "");
  }
  if (ab_suffix.size() > 0 && ab_suffix[0] != '_') {
    ab_suffix = std::string("_") + ab_suffix;
  }
  return ab_suffix;
}

}  // namespace

int main(int argc, char* argv[]) {
  int ret;
  AvbOps* ops = nullptr;
  std::string ab_suffix = get_ab_suffix();

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

  if (strcmp(argv[1], "disable-verity") == 0) {
    ret = do_set_verity(ops, ab_suffix, false);
  } else if (strcmp(argv[1], "enable-verity") == 0) {
    ret = do_set_verity(ops, ab_suffix, true);
  } else if (strcmp(argv[1], "get-verity") == 0) {
    ret = do_get_verity(ops, ab_suffix);
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
