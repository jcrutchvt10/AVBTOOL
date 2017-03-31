# Android Verified Boot 2.0

This repository contains tools and libraries for working with Android
Verified Boot 2.0. Usually AVB is used to refer to this codebase.

## Introduction

The main job of `avbtool` is to create `vbmeta.img` which is the
top-level object for verified boot. This image is designed to go into
the `vbmeta` partition (or, if using A/B, the slot in question
e.g. `vbmeta_a` or `vbmeta_b`) and be of minimal size (for out-of-band
updates). The vbmeta image is cryptographically signed and contains
verification data (e.g. cryptographic digests) for verifying
`boot.img`, `system.img`, and other partitions/images.

The vbmeta image can also contain references to other partitions where
verification data is stored as well as a public key indicating who
should sign the verification data. This indirection provides
delegation, that is, it allows a 3rd party to control content on a
given partition by including their public key in `vbmeta.img`. By
design, this authority can be easily revoked by simply updating
`vbmeta.img` with new descriptors for the partition in question.

Storing signed verification data on other images - for example
`boot.img` and `system.img` - is also done with `avbtool`.

In addition to `avbtool`, a library - `libavb` - is provided. This
library performs all verification on the device side e.g. it starts by
loading the vbmeta partition, checks the signature, and then goes on
to load the boot partition for verification. This library is intended
to be used in both boot loaders and inside Android. It has a simple
abstraction for system dependencies (see `avb_sysdeps.h`) as well as
operations that the boot loader or OS is expected to implement (see
`avb_ops.h`). The main entry point for verification is
`avb_slot_verify()`.

It is expected that most devices will use A/B (e.g. multiple copies of
the OS in separate so-called 'slots') in addition to AVB. While
managing A/B metadata and associated metadata (e.g. managing
`stored_rollback_index[n]` locations) is outside the scope of
`libavb`, enough interfaces are exposed so the boot loader can
integrate its A/B stack with `libavb`. In particular
`avb_slot_verify()` takes a `slot_suffix` parameter and its result
struct `AvbSlotVerifyData` convey the rollback indexes in the image
that was verified.

AVB also includes an A/B implementation that boot loaders may
optionally use. This implementation is in the `libavb_ab` library and
integrates with image verification including updating the
`stored_rollback_index[n]` locations on the device as needed. The
bootloader can use this through the `avb_ab_flow()` function which in
turn calls `avb_slot_verify()` as needed.

In `libavb_ab`, A/B metadata is stored in the `misc` partition using a
format private to `libavb_ab` in the location on `misc` reserved for
this. For more information about the `misc.img` file format see
the
[bootloader_message.h](https://android.googlesource.com/platform/bootable/recovery/+/master/bootloader_message/include/bootloader_message/bootloader_message.h) file
in AOSP. A/B metadata can be written to `misc.img` using the
`set_ab_metadata` sub-command of `avbtool`. A/B metadata is comprised
of data for each slo and per-slot metadata has a priority field (0 to
15), number of tries remaining for attempting to boot the slot (0 to
7), and a flag to indicate whether the slot has successfully booted.

A/B metadata integrity is provided by a simple magic marker and a
CRC-32 checksum. If invalid A/B metadata is detected, the behavior is
to reset the A/B metadata to a known state where both slots are given
seven boot tries.

An implementation of a boot_control HAL using AVB-specific A/B
metadata is also provided.

Android Things has specific requirements and validation logic for the
vbmeta public key. An extension is provided in `libavb_atx` which
performs this validation as an implementatio of `libavb`'s public key
validation operation (see `avb_validate_vbmeta_public_key()` in
`avb_ops.h`).

## Files and Directories

* `libavb/`
    + An implementation of image verification. This code is designed
      to be highly portable so it can be used in as many contexts as
      possible. This code requires a C99-compliant C compiler. Part of
      this code is considered internal to the implementation and
      should not be used outside it. For example, this applies to the
      `avb_rsa.[ch]` and `avb_sha.[ch]` files. System dependencies
      expected to be provided by the platform is defined in
      `avb_sysdeps.h`. If the platform provides the standard C runtime
      `avb_sysdeps_posix.c` can be used.
* `libavb_ab/`
    + An A/B implementation for use in boot loaders.
* `libavb_atx/`
    + An Android Things Extension for validating public key metadata.
* `libavb_user/`
    + Contains an AvbOps implementation suitable for use in userspace
      on the device (used in boot_control.avb and avbctl).
* `boot_control/`
    + An implemementation of the Android boot_control HAL for use with
      boot loaders using `libavb_ab`.
* `Android.mk`
    + Build instructions for building libavb (a static library for use
      on the device), host-side libraries (for unit tests), and unit
      tests.
* `avbtool`
    + A tool written in Python for working with images related to
      verified boot.
* `test/`
    + Unit tests for `abvtool`, `libavb`, `libavb_ab`, and
      `libavb_atx`.
* `tools/avbctl/`
    + Contains the source-code for a tool that can be used to control
      AVB at runtime.
* `examples/uefi/`
    + Contains the source-code for a UEFI-based boot-loader utilizing
      `libavb/` and `libavb_ab/`.

## Audience and portability notes

This code is intended to be used in bootloaders in devices running
Android. The suggested approach is to copy the appropriate header and
C files mentioned in the previous section into the boot loader and
integrate as appropriate.

The `libavb/` and `libavb_ab/` codebase will evolve over time so
integration should be as non-invasive as possible. The intention is to
keep the API of the library stable however it will be broken if
necessary. As for portability, the library is intended to be highly
portable, work on both little- and big-endian architectures and 32-
and 64-bit. It's also intended to work in non-standard environments
without the standard C library and runtime.

If the `AVB_ENABLE_DEBUG` preprocessor symbol is set, the code will
include useful debug information and run-time checks. Production
builds should not use this. The preprocessor symbol `AVB_COMPILATION`
should be set only when compiling the libraries. The code must be
compiled into a separate libraries.

Applications using the compiled `libavb` library must only include the
`libavb/libavb.h` file (which will include all public interfaces) and
must not have the `AVB_COMPILATION` preprocessor symbol set. This is
to ensure that internal code that may be change in the future (for
example `avb_sha.[ch]` and `avb_rsa.[ch]`) will not be visible to
application code.

## Versioning and compatibility

AVB uses a version number with three fields - the major, minor, and
sub version. Here's an example version number

                         1.4.3
                         ^ ^ ^
                         | | |
    the major version ---+ | |
    the minor version -----+ |
      the sub version -------+

The major version number is bumped only if compatibility is broken,
e.g. a struct field has been removed or changed. The minor version
number is bumped only if a new feature is introduced, for example a
new algorithm or descriptor has been added. The sub version number is
bumped when bugs are fixed or other changes not affecting
compatibility are made.

The `AvbVBMetaImageHeader` struct (as defined in the
`avb_vbmeta_image.h`) carries the major and minor version number of
`libavb` required to verify the struct in question. This is stored in
the `required_libavb_version_major` and
`required_libavb_version_minor` fields. Additionally this struct
contains a textual field with the version of `avbtool` used to create
the struct, for example "avbtool 1.4.3" or "avbtool 1.4.3 some_board
Git-4589fbec".

Note that it's entirely possible to have a `AvbVBMetaImageHeader`
struct with

    required_libavb_version_major = 1
    required_libavb_version_minor = 0
    avbtool_release_string = "avbtool 1.4.3"

if, for example, creating an image that does not use any features
added after AVB version 1.0.

## Adding new features

If adding a new feature for example a new algorithm or a new
descriptor then `AVB_VERSION_MINOR` in `avb_version.h` and `avbtool`
must be bumped and `AVB_VERSION_SUB` should be set to zero.

Unit tests **MUST** be added to check that

* The feature is used if - and only if - suitable commands/options are
  passed to `avbtool`.
* The `required_version_minor` field is set to the bumped value if -
  and only if - the feature is used.

If `AVB_VERSION_MINOR` has already been bumped since the last release
there is obviously no need to bump it again.

## Usage

The content for the vbmeta partition can be generated as follows:

    $ avbtool make_vbmeta_image                                                    \
        --output OUTPUT                                                            \
        [--algorithm ALGORITHM] [--key /path/to/key_used_for_signing_or_pub_key]   \
        [--public_key_metadata /path/to/pkmd.bin] [--rollback_index NUMBER]        \
        [--include_descriptors_from_footer /path/to/image.bin]                     \
        [--setup_rootfs_from_kernel /path/to/image.bin]                            \
        [--chain_partition part_name:rollback_index_location:/path/to/key1.bin]    \
        [--signing_helper /path/to/external/signer]                                \
        [--append_to_release_string STR]

An integrity footer containing the hash for an entire partition can be
added to an existing image as follows:

    $ avbtool add_hash_footer                                                      \
        --image IMAGE                                                              \
        --partition_name PARTNAME --partition_size SIZE                            \
        [--algorithm ALGORITHM] [--key /path/to/key_used_for_signing_or_pub_key]   \
        [--public_key_metadata /path/to/pkmd.bin] [--rollback_index NUMBER]        \
        [--hash_algorithm HASH_ALG] [--salt HEX]                                   \
        [--include_descriptors_from_footer /path/to/image.bin]                     \
        [--setup_rootfs_from_kernel /path/to/image.bin]                            \
        [--output_vbmeta_image OUTPUT_IMAGE] [--do_not_append_vbmeta_image]        \
        [--signing_helper /path/to/external/signer]                                \
        [--append_to_release_string STR]

An integrity footer containing the root digest and salt for a hashtree
for a partition can be added to an existing image as follows. The
hashtree is also appended to the image.

    $ avbtool add_hashtree_footer                                                  \
        --image IMAGE                                                              \
        --partition_name PARTNAME --partition_size SIZE                            \
        [--algorithm ALGORITHM] [--key /path/to/key_used_for_signing_or_pub_key]   \
        [--public_key_metadata /path/to/pkmd.bin] [--rollback_index NUMBER]        \
        [--hash_algorithm HASH_ALG] [--salt HEX] [--block_size SIZE]               \
        [--include_descriptors_from_footer /path/to/image.bin]                     \
        [--setup_rootfs_from_kernel /path/to/image.bin]                            \
        [--output_vbmeta_image OUTPUT_IMAGE] [--do_not_append_vbmeta_image]        \
        [--generate_fec] [--fec_num_roots FEC_NUM_ROOTS]                           \
        [--signing_helper /path/to/external/signer]                                \
        [--append_to_release_string STR]

The integrity footer on an image can be removed from an image. The
hashtree can optionally be kept in place.

    $ avbtool erase_footer --image IMAGE [--keep_hashtree]

For hash- and hashtree-images the vbmeta struct can also be written to
an external file via the `--output_vbmeta_image` option and one can
also specify that the vbmeta struct and footer not be added to the
image being operated on.

To calculate the maximum size of an image that will fit in a partition
of a given size after having used the `avbtool add_hashtree_footer`
command on it, use the `--calc_max_image_size` option:

    $ avbtool add_hashtree_footer --partition_size $((10*1024*1024)) \
        --calc_max_image_size
    10330112

The `--signing_helper` option can be used in `make_vbmeta_image`,
`add_hash_footer` and `add_hashtree_footer` commands to specify any
external program for signing hashes. The data to sign (including
padding e.g. PKCS1-v1.5) is fed via `STDIN` and the signed data is
returned via `STDOUT`. If `--signing_helper` is present in a command
line, the `--key` option need only contain a public key. Arguments for
a signing helper are `algorithm` and `public key`. If the signing
helper exits with a non-zero exit code, it means failure.

Here's an example invocation:

    /path/to/my_signing_program SHA256_RSA2048 /path/to/publickey.pem

The `append_vbmeta_image` command can be used to append an entire
vbmeta blob to the end of another image. This is useful for cases when
not using any vbmeta partitions, for example:

    $ cp boot.img boot-with-vbmeta-appended.img
    $ avbtool append_vbmeta_image                       \
        --image boot-with-vbmeta-appended.img           \
        --partition_size SIZE_OF_BOOT_PARTITION         \
        --vbmeta_image vbmeta.img
    $ fastboot flash boot boot-with-vbmeta-appended.img

## Build system integration notes

Android Verified Boot is enabled by the `BOARD_AVB_ENABLE` variable

    BOARD_AVB_ENABLE := true

This will make the build system create `vbmeta.img` which will contain
a hash descriptor for `boot.img`, a hashtree descriptor for
`system.img`, a kernel-cmdline descriptor for setting up `dm-verity`
for `system.img` and append a hash-tree to `system.img`.

By default, the algorithm `SHA256_RSA4096` is used with a test key
from the `external/avb/test/data` directory. This can be overriden by
the `BOARD_AVB_ALGORITHM` and `BOARD_AVB_KEY_PATH` variables to use
e.g. a 4096-bit RSA key and SHA-512:

    BOARD_AVB_ALGORITHM := SHA512_RSA4096
    BOARD_AVB_KEY_PATH := /path/to/rsa_key_4096bits.pem

Remember that the public part of this key needs to be available to the
bootloader of the device expected to verify resulting images. Use
`avbtool extract_public_key` to extract the key in the expected format
(**AVB_pk** in the following). If the device is using a different root
of trust than **AVB_pk** the `--public_key_metadata` option can be
used to embed a blob (**AVB_pkmd** in the following) that can be used
to e.g. derive **AVB_pk**. Both **AVB_pk** and **AVB_pkmd** are passed
to the `validate_vbmeta_public_key()` operation when verifying a slot.

To prevent rollback attacks, the rollback index should be increased on
a regular basis. The rollback index can be set with the
`BOARD_AVB_ROLLBACK_INDEX` variable:

     BOARD_AVB_ROLLBACK_INDEX := 5

If this is not set, the rollback index defaults to 0.

The variable `BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS` can be used to specify
additional options passed to `avbtool make_vbmeta_image`. Typical
options to be used here include `--prop`, `--prop_from_file`, and
`--chain_partition`.

The variable `BOARD_AVBTOOL_BOOT_ADD_HASH_FOOTER_ARGS` can be used to
specify additional options passed to `avbtool add_hash_footer` for
`boot.img`. Typical options to be used here include `--hash_algorithm`
and `--salt`.

The variable `BOARD_AVBTOOL_SYSTEM_ADD_HASHTREE_FOOTER_ARGS` can be
used to specify additional options passed to `avbtool
add_hashtree_footer` for `system.img`. Typical options to be used here
include `--hash_algorithm`, `--salt`, `--block_size`, and
`--generate_fec`.

Build system variables (such as `PRODUCT_SUPPORTS_VERITY_FEC`) used
for previous version of Verified Boot in Android are not used in AVB
