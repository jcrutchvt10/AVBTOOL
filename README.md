# Android Verified Boot 2.0
---

This repository contains tools and libraries for working with Android
Verified Boot 2.0. Usually AVB is used to refer to this codebase.

# Table of Contents

* [What is it?](#What-is-it)
    + [The VBMeta struct](#The-VBMeta-struct)
    + [Rollback Protection](#Rollback-Protection)
    + [A/B Support](#A_B-Support)
* [Tools and Libraries](#Tools-and-Libraries)
    + [avbtool and libavb](#avbtool-and-libavb)
    + [Files and Directories](#Files-and-Directories)
    + [Portability](#Portability)
    + [Versioning and Compatibility](#Versioning-and-Compatibility)
    + [Adding New Features](#Adding-New-Features)
    + [Using avbtool](#Using-avbtool)
    + [Build System Integration](#Build-System-Integration)
* [Device Integration](#Device-Integration)
    + [System Dependencies](#System-Dependencies)
    + [Locked and Unlocked mode](#Locked-and-Unlocked-mode)
    + [Tamper-evident Storage](#Tamper_evident-Storage)
    + [Updating Stored Rollback Indexes](#Updating-Stored-Rollback-Indexes)
    + [Recommended Bootflow](#Recommended-Bootflow)
    + [Handling dm-verity Errors](#Handling-dm_verity-Errors)
    + [Android Specific Integration](#Android-Specific-Integration)

# What is it?

Verified boot is the process of assuring the end user of the integrity
of the software running on a device. It typically starts with a
read-only portion of the device firmware which loads code and executes
it only after cryptographically verifying that the code is authentic
and doesn't have any known security flaws. AVB is one implementation
of verified boot.

## The VBMeta struct

The central data structure used in AVB is the VBMeta struct. This data
structure contains a number of descriptors (and other metadata) and
all of this data is cryptographically signed. Descriptors are used for
image hashes, image hashtree metadata, and so-called *chained
partitions*. A simple example is the following:

![AVB with boot, system, and vendor](docs/avb-integrity-data-in-vbmeta.png)

where the `vbmeta` partition holds the hash for the `boot` partition
in a hash descriptor. For the `system` and `vendor` partitions a
hashtree follows the filesystem data and the `vbmeta` partition holds
the root hash, salt, and offset of the hashtree in hashtree
descriptors. Because the VBMeta struct in the `vbmeta` partition is
cryptographically signed, the boot loader can check the signature and
verify it was made by the owner of `key0` (by e.g. embedding the
public part of `key0`) and thereby trust the hashes used for `boot`,
`system`, and `vendor`.

A chained partition descriptor is used to delegate authority - it
contains the name of the partition where authority is delegated as
well as the public key that is trusted for signatures on this
particular partition. As an example, consider the following setup:

![AVB with a chained partition](docs/avb-chained-partition.png)

In this setup the `xyz` partition has a hashtree for
integrity-checking. Following the hashtree is a VBMeta struct which
contains the hashtree descriptor with hashtree metadata (root hash,
salt, offset, etc.) and this struct is signed with `key1`. Finally, at
the end of the partition is a footer which has the offset of the
VBMeta struct.

This setup allows the bootloader to use the chain partition descriptor
to find the footer at the end of the partition (using the name in the
chain partition descriptor) which in turns helps locate the VBMeta
struct and verify that it was signed by `key1` (using `key1_pub` stored in the
chain partition descriptor). Crucially, because there's a footer with
the offset, the `xyz` partition can be updated without the `vbmeta`
partition needing any changes.

The VBMeta struct is flexible enough to allow hash descriptors and
hashtree descriptors for any partition to live in either the `vbmeta`
partition or - via a chain partition descriptor - in the partition
that they are used to integrity check. This allows for a wide range of
organizational and trust relationships.

## Rollback Protection

AVB includes Rollback Protection which is used to protect against
known security flaws. Each VBMeta struct has a *rollback index* baked
into it like the following:

![AVB rollback indexes](docs/avb-rollback-indexes.png)

These numbers are referred to as `rollback_index[n]` and are increased
for each image as security flaws are discovered and
fixed. Additionally the device stores the last seen rollback index in
tamper-evident storage:

![AVB stored rollback indexes](docs/avb-stored-rollback-indexes.png)

and these are referred to as `stored_rollback_index[n]`.

Rollback protection is having the device reject an image unless
`rollback_index[n]` >= `stored_rollback_index[n]` for all `n`, and
having the device increase `stored_rollback_index[n]` over
time. Exactly how this is done is discussed in
the
[Updating Stored Rollback Indexes](#Updating-Stored-Rollback-Indexes)
section.

## A/B Support

AVB has been designed to work with A/B by requiring that the A/B
suffix is never used in any partition names stored in
descriptors. Here's an example with two slots:

![AVB with A/B partitions](docs/avb-ab-partitions.png)

Note how the rollback indexes differ between slots - for slot A the
rollback indexes are `[42, 101]` and for slot B they are `[43, 103]`.

# Tools and Libraries

This section contains information about the tools and libraries
included in AVB.

## avbtool and libavb

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
loading the `vbmeta` partition, checks the signature, and then goes on
to load the `boot` partition for verification. This library is
intended to be used in both boot loaders and inside Android. It has a
simple abstraction for system dependencies (see `avb_sysdeps.h`) as
well as operations that the boot loader or OS is expected to implement
(see `avb_ops.h`). The main entry point for verification is
`avb_slot_verify()`.

Android Things has specific requirements and validation logic for the
vbmeta public key. An extension is provided in `libavb_atx` which
performs this validation as an implementation of `libavb`'s public key
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
    + An experimental A/B implementation for use in boot loaders
      and AVB examples.
* `libavb_atx/`
    + An Android Things Extension for validating public key metadata.
* `libavb_user/`
    + Contains an `AvbOps` implementation suitable for use in Android
      userspace. This is used in `boot_control.avb` and `avbctl`.
* `boot_control/`
    + An implementation of the Android `boot_control` HAL for use with
      boot loaders using the experimental `libavb_ab` A/B stack.
* `Android.bp`
    + Build instructions for building `libavb` (a static library for use
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
      AVB at runtime in Android.
* `examples/uefi/`
    + Contains the source-code for a UEFI-based boot-loader utilizing
      `libavb/` and `libavb_ab/`.
* `README.md`
    + This file.
* `docs/`
    + Contains documentation files.

## Portability

The `libavb` code is intended to be used in bootloaders in devices
that will load Android or other operating systems. The suggested
approach is to copy the appropriate header and C files mentioned in
the previous section into the boot loader and integrate as
appropriate.

As the `libavb/` codebase will evolve over time integration should be
as non-invasive as possible. The intention is to keep the API of the
library stable however it will be broken if necessary. As for
portability, the library is intended to be highly portable, work on
both little- and big-endian architectures and 32- and 64-bit. It's
also intended to work in non-standard environments without the
standard C library and runtime.

If the `AVB_ENABLE_DEBUG` preprocessor symbol is set, the code will
include useful debug information and run-time checks. Production
builds should not use this. The preprocessor symbol `AVB_COMPILATION`
should be set only when compiling the libraries. The code must be
compiled into a separate library.

Applications using the compiled `libavb` library must only include the
`libavb/libavb.h` file (which will include all public interfaces) and
must not have the `AVB_COMPILATION` preprocessor symbol set. This is
to ensure that internal code that may be change in the future (for
example `avb_sha.[ch]` and `avb_rsa.[ch]`) will not be visible to
application code.

## Versioning and Compatibility

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

## Adding New Features

If adding a new feature for example a new algorithm or a new
descriptor then `AVB_VERSION_MINOR` in `avb_version.h` and `avbtool`
must be bumped and `AVB_VERSION_SUB` should be set to zero.

Unit tests **MUST** be added to check that

* The feature is used if - and only if - suitable commands/options are
  passed to `avbtool`.
* The `required_version_minor` field is set to the bumped value if -
  and only if - the feature is used. Also add tests to check that the
  correct value is output when `--print_required_libavb_version` is
  used.

If `AVB_VERSION_MINOR` has already been bumped since the last release
there is obviously no need to bump it again.

## Using avbtool

The content for the vbmeta partition can be generated as follows:

    $ avbtool make_vbmeta_image                                                    \
        [--output OUTPUT]                                                          \
        [--algorithm ALGORITHM] [--key /path/to/key_used_for_signing_or_pub_key]   \
        [--public_key_metadata /path/to/pkmd.bin] [--rollback_index NUMBER]        \
        [--include_descriptors_from_image /path/to/image.bin]                      \
        [--setup_rootfs_from_kernel /path/to/image.bin]                            \
        [--chain_partition part_name:rollback_index_location:/path/to/key1.bin]    \
        [--signing_helper /path/to/external/signer]                                \
        [--signing_helper_with_files /path/to/external/signer_with_files]          \
        [--print_required_libavb_version]                                          \
        [--append_to_release_string STR]

An integrity footer containing the hash for an entire partition can be
added to an existing image as follows:

    $ avbtool add_hash_footer                                                      \
        --partition_name PARTNAME --partition_size SIZE                            \
        [--image IMAGE]                                                            \
        [--algorithm ALGORITHM] [--key /path/to/key_used_for_signing_or_pub_key]   \
        [--public_key_metadata /path/to/pkmd.bin] [--rollback_index NUMBER]        \
        [--hash_algorithm HASH_ALG] [--salt HEX]                                   \
        [--include_descriptors_from_image /path/to/image.bin]                      \
        [--setup_rootfs_from_kernel /path/to/image.bin]                            \
        [--output_vbmeta_image OUTPUT_IMAGE] [--do_not_append_vbmeta_image]        \
        [--signing_helper /path/to/external/signer]                                \
        [--signing_helper_with_files /path/to/external/signer_with_files]          \
        [--print_required_libavb_version]                                          \
        [--append_to_release_string STR]                                           \
        [--calc_max_image_size]

An integrity footer containing the root digest and salt for a hashtree
for a partition can be added to an existing image as follows. The
hashtree is also appended to the image.

    $ avbtool add_hashtree_footer                                                  \
        --partition_name PARTNAME --partition_size SIZE                            \
        [--image IMAGE]                                                            \
        [--algorithm ALGORITHM] [--key /path/to/key_used_for_signing_or_pub_key]   \
        [--public_key_metadata /path/to/pkmd.bin] [--rollback_index NUMBER]        \
        [--hash_algorithm HASH_ALG] [--salt HEX] [--block_size SIZE]               \
        [--include_descriptors_from_image /path/to/image.bin]                      \
        [--setup_rootfs_from_kernel /path/to/image.bin]                            \
        [--setup_as_rootfs_from_kernel]                                            \
        [--output_vbmeta_image OUTPUT_IMAGE] [--do_not_append_vbmeta_image]        \
        [--do_not_generate_fec] [--fec_num_roots FEC_NUM_ROOTS]                    \
        [--signing_helper /path/to/external/signer]                                \
        [--signing_helper_with_files /path/to/external/signer_with_files]          \
        [--print_required_libavb_version]                                          \
        [--append_to_release_string STR]                                           \
        [--calc_max_image_size]

The size of an image with integrity footers can be changed using the
`resize_image` command:

    $ avbtool resize_image                                                         \
        --image IMAGE                                                              \
        --partition_size SIZE

The integrity footer on an image can be removed from an image. The
hashtree can optionally be kept in place.

    $ avbtool erase_footer --image IMAGE [--keep_hashtree]

For hash- and hashtree-images the vbmeta struct can also be written to
an external file via the `--output_vbmeta_image` option and one can
also specify that the vbmeta struct and footer not be added to the
image being operated on.

To calculate the maximum size of an image that will fit in a partition
of a given size after having used the `avbtool add_hash_footer` or
`avbtool add_hashtree_footer` commands on it, use the
`--calc_max_image_size` option:

    $ avbtool add_hash_footer --partition_size $((10*1024*1024)) \
        --calc_max_image_size
    10416128

    $ avbtool add_hashtree_footer --partition_size $((10*1024*1024)) \
        --calc_max_image_size
    10330112

To calculate the required libavb version that would be put in the
vbmeta struct when using `make_vbmeta_image`, `add_hash_footer`, and
`add_hashtree_footer` commands use the
`--print_required_libavb_version` option:

    $ avbtool make_vbmeta_image \
        --algorithm SHA256_RSA2048 --key /path/to/key.pem \
        --include_descriptors_from_image /path/to/boot.img \
        --include_descriptors_from_image /path/to/system.img \
        --print_required_libavb_version
    1.0

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

The `--signing_helper_with_files` is similar to `--signing_helper`
except that a temporary file is used to communicate with the helper
instead of `STDIN` and `STDOUT`. This is useful in situations where
the signing helper is using code which is outputting diagnostics on
`STDOUT` instead of `STDERR`. Here's an example invocation

    /path/to/my_signing_program_with_files SHA256_RSA2048 \
      /path/to/publickey.pem /tmp/path/to/communication_file

where the last positional argument is a file that contains the data to
sign. The helper should write the signature in this file.

The `append_vbmeta_image` command can be used to append an entire
vbmeta blob to the end of another image. This is useful for cases when
not using any vbmeta partitions, for example:

    $ cp boot.img boot-with-vbmeta-appended.img
    $ avbtool append_vbmeta_image                       \
        --image boot-with-vbmeta-appended.img           \
        --partition_size SIZE_OF_BOOT_PARTITION         \
        --vbmeta_image vbmeta.img
    $ fastboot flash boot boot-with-vbmeta-appended.img

The `verify_image` command can be used to verify the contents of
several image files at the same time. When invoked on an image the
following checks are performed:

* If the image has a VBMeta struct the signature is checked against
  the embedded public key. If the image doesn't look like `vbmeta.img`
  then a footer is looked for and used if present.

* If the option `--key` is passed then a `.pem` file is expected and
  it's checked that the embedded public key in said VBMeta struct
  matches the given key.

* All descriptors in the VBMeta struct are checked in the following
  way:
    + For a hash descriptor the image file corresponding to the
      partition name is loaded and its digest is checked against that
      in the descriptor.
    + For a hashtree descriptor the image file corresponding to the
      partition name is loaded and the hashtree is calculated and its
      root digest compared to that in the descriptor.
    + For a chained partition descriptor its contents is compared
      against content that needs to be passed in via the
      `--expected_chain_partition` options. The format for this option
      is similar to that of the `--chain_partition` option. If there
      is no `--expected_chain_partition` descriptor for the chain
      partition descriptor the check fails.

Here's an example for a setup where the digests for `boot.img` and
`system.img` are stored in `vbmeta.img` which is signed with
`my_key.pem`. It also checks that the chain partition for partition
`foobar` uses rollback index 8 and that the public key in AVB format
matches that of the file `foobar_vendor_key.avbpubkey`:

    $ avbtool verify_image \
         --image /path/to/vbmeta.img \
         --key my_key.pem \
         --expect_chained_partition foobar:8:foobar_vendor_key.avbpubkey

    Verifying image /path/to/vbmeta.img using key at my_key.pem
    vbmeta: Successfully verified SHA256_RSA4096 vbmeta struct in /path_to/vbmeta.img
    boot: Successfully verified sha256 hash of /path/to/boot.img for image of 10543104 bytes
    system: Successfully verified sha1 hashtree of /path/to/system.img for image of 1065213952 bytes
    foobar: Successfully verified chain partition descriptor matches expected data

In this example the `verify_image` command verifies the files
`vbmeta.img`, `boot.img`, and `system.img` in the directory
`/path/to`. The directory and file extension of the given image
(e.g. `/path/to/vbmeta.img`) is used together with the partition name
in the descriptor to calculate the filenames of the images holding
hash and hashtree images.

The `verify_image` command can also be used to check that a custom
signing helper works as intended.

## Build System Integration

In Android, AVB is enabled by the `BOARD_AVB_ENABLE` variable

    BOARD_AVB_ENABLE := true

This will make the build system create `vbmeta.img` which will contain
a hash descriptor for `boot.img`, a hashtree descriptor for
`system.img`, a kernel-cmdline descriptor for setting up `dm-verity`
for `system.img` and append a hash-tree to `system.img`. If the build
system is set up such that `vendor.img` is being built, a hash-tree
will also be appended to this image and its hash-tree descriptor will
be included in `vbmeta.img`.

By default, the algorithm `SHA256_RSA4096` is used with a test key
from the `external/avb/test/data` directory. This can be overriden by
the `BOARD_AVB_ALGORITHM` and `BOARD_AVB_KEY_PATH` variables to use
e.g. a 4096-bit RSA key and SHA-512:

    BOARD_AVB_ALGORITHM := SHA512_RSA4096
    BOARD_AVB_KEY_PATH := /path/to/rsa_key_4096bits.pem

Remember that the public part of this key needs to be available to the
bootloader of the device expected to verify resulting images. Use
`avbtool extract_public_key` to extract the key in the expected format
(`AVB_pk` in the following). If the device is using a different root
of trust than `AVB_pk` the `--public_key_metadata` option can be used
to embed a blob (`AVB_pkmd` in the following) that can be used to
e.g. derive `AVB_pk`. Both `AVB_pk` and `AVB_pkmd` are passed to the
`validate_vbmeta_public_key()` operation when verifying a slot.

To prevent rollback attacks, the rollback index should be increased on
a regular basis. The rollback index can be set with the
`BOARD_AVB_ROLLBACK_INDEX` variable:

     BOARD_AVB_ROLLBACK_INDEX := 5

If this is not set, the rollback index defaults to 0.

The variable `BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS` can be used to specify
additional options passed to `avbtool make_vbmeta_image`. Typical
options to be used here include `--prop`, `--prop_from_file`,
`--chain_partition`, `--public_key_metadata`, and `--signing_helper`.

The variable `BOARD_AVB_BOOT_ADD_HASH_FOOTER_ARGS` can be used to
specify additional options passed to `avbtool add_hash_footer` for
`boot.img`. Typical options to be used here include `--hash_algorithm`
and `--salt`.

The variable `BOARD_AVB_SYSTEM_ADD_HASHTREE_FOOTER_ARGS` can be used
to specify additional options passed to `avbtool add_hashtree_footer`
for `system.img`. Typical options to be used here include
`--hash_algorithm`, `--salt`, `--block_size`, and
`--do_not_generate_fec`.

The variable `BOARD_AVB_VENDOR_ADD_HASHTREE_FOOTER_ARGS` can be used
to specify additional options passed to `avbtool add_hashtree_footer`
for `vendor.img`. Typical options to be used here include
`--hash_algorithm`, `--salt`, `--block_size`, and
`--do_not_generate_fec`.

The variable `BOARD_AVB_DTBO_ADD_HASH_FOOTER_ARGS` can be used to
specify additional options passed to `avbtool add_hash_footer` for
`dtbo.img`. Typical options to be used here include `--hash_algorithm`
and `--salt`.

Build system variables (such as `PRODUCT_SUPPORTS_VERITY_FEC`) used
for previous version of Verified Boot in Android are not used in AVB.

# Device Integration

This section discusses recommendations and best practices for
integrating `libavb` with a device boot loader. It's important to
emphasize that these are just recommendations so the use of the word
`must` should be taken lightly.

Additionally term *HLOS* is used in this chapter to refer to the *High
Level Operating System*. This obviously includes Android (including
other form-factors than phones) but could also be other operating
systems.

## System Dependencies

The `libavb` library is written in a way so it's portable to any
system with a C99 compiler. It does not require the standard C library
however the boot loader must implement a simple set of system
primitives required by `libavb` such as `avb_malloc()`, `avb_free()`,
and `avb_print()`.

In addition to the system primitives, `libavb` interfaces with the boot
loader through the supplied `AvbOps` struct. This includes operations
to read and write data from partitions, read and write rollback
indexes, check if the public key used to make a signature should be
accepted, and so on.

## Locked and Unlocked mode

AVB has been designed to support the notion of the device being either
LOCKED state or UNLOCKED state as used in Android.

In the context of AVB, the LOCKED state means that verification errors
are fatal whereas in UNLOCKED state they are not. If the device is
UNLOCKED pass `AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR` flag in
the `flags` parameter of `avb_slot_verify()` and treat verification
errors including

* `AVB_SLOT_VERIFY_RESULT_ERROR_PUBLIC_KEY_REJECTED`
* `AVB_SLOT_VERIFY_RESULT_ERROR_VERIFICATION`
* `AVB_SLOT_VERIFY_RESULT_ERROR_ROLLBACK_INDEX`

as non-fatal. If the device is in the LOCKED state, don't pass the
`AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR` flag in the `flags`
parameter of `avb_slot_verify()` and only treat
`AVB_SLOT_VERIFY_RESULT_OK` as non-fatal.

On Android, device state may be altered through the fastboot interface
using, e.g. `fastboot flashing lock` (to transition to the LOCKED
state) and `fastboot flashing unlock` (to transition to the UNLOCKED
state).

The device must only allow state transitions (e.g. from LOCKED to
UNLOCKED or UNLOCKED to LOCKED) after asserting physical presence of
the user. If the device has a display and buttons this is typically
done by showing a dialog and requiring the user to confirm or cancel
using physical buttons.

All user data must be cleared when transitioning from the LOCKED to
the UNLOCKED state (including the `userdata` partition and any NVRAM
spaces). Additionally all `stored_rollback_index[n]` locations must be
cleared (all elements must be set to zero). Similar action (erasing
`userdata`, NVRAM spaces, and `stored_rollback_index[n]` locations)
shall also happening when transitioning from UNLOCKED to LOCKED. If
the device is required to use full disk encryption, then a less
intensive wipe is required for UNLOCKED to LOCKED. Depending on the
device form-factor and intended use, the user should be prompted to
confirm before any data is erased.

## Tamper-evident Storage

In this document, *tamper-evident* means that it's possible to detect
if the HLOS has tampered with the data, e.g. if it has been
overwritten.

Tamper-evident storage must be used for stored rollback indexes, keys
used for verification, and device state (whether the device is LOCKED
or UNLOCKED). If tampering has been detected the corresponding
`AvbOps` operation should fail by e.g. returning
`AVB_IO_RESULT_ERROR_IO`. It is especially important that verification
keys cannot be tampered with since they represent the root-of-trust.

If verification keys are mutable they must only be set by the end
user, e.g. it must never be set at the factory or store or any
intermediate point before the end user. Additionally, it must only be
possible to set or clear a key while the device is in the UNLOCKED
state.

## Updating Stored Rollback Indexes

In order for Rollback Protection to work the bootloader will need to
update the `stored_rollback_indexes[n]` array on the device prior to
transferring control to the HLOS. If not using A/B this is
straightforward - just update it to what's in the AVB metadata for the
slot before booting. In pseudo-code it would look like this:

```c++
// The |slot_data| parameter should be the AvbSlotVerifyData returned
// by avb_slot_verify() for the slot we're about to boot.
//
bool update_stored_rollback_indexes_for_slot(AvbOps* ops,
                                             AvbSlotVerifyData* slot_data) {
    for (int n = 0; n < AVB_MAX_NUMBER_OF_ROLLBACK_INDEX_LOCATIONS; n++) {
        uint64_t rollback_index = slot_data->rollback_indexes[n];
        if (rollback_index > 0) {
            AvbIOResult io_ret;
            uint64_t current_stored_rollback_index;

            io_ret = ops->read_rollback_index(ops, n, &current_stored_rollback_index);
            if (io_ret != AVB_IO_RESULT_OK) {
                return false;
            }

            if (rollback_index > current_stored_rollback_index) {
                io_ret = ops->write_rollback_index(ops, n, rollback_index);
                if (io_ret != AVB_IO_RESULT_OK) {
                    return false;
                }
            }
        }
    }
    return true;
}
```

However if using A/B more care must be taken to still allow the device
to fall back to the old slot if the update didn't work.

For an HLOS like Android where rollback is only supported if the
updated OS version is found to not work, `stored_rollback_index[n]`
should only be updated from slots that are marked as SUCCESSFUL in the
A/B metadata. The pseudo-code for that is as follows where
`is_slot_is_marked_as_successful()` comes from the A/B stack in use:

```c++
if (is_slot_is_marked_as_successful(slot->ab_suffix)) {
    if (!update_stored_rollback_indexes_for_slot(ops, slot)) {
        // TODO: handle error.
    }
}
```

For an HLOS where it's possible to roll back to a previous version,
`stored_rollback_index[n]` should be set to the largest possible value
allowing all bootable slots to boot. This approach is implemented in
AVB's experimental A/B stack `libavb_ab`, see the `avb_ab_flow()`
implementation. Note that this requires verifying *all* bootable slots
at every boot and this may impact boot time.

## Recommended Bootflow

The recommended boot flow for a device using AVB is as follows:

![Recommended AVB boot flow](docs/avb-recommended-boot-flow.png)

Notes:

* The device is expected to search through all A/B slots until it
  finds a valid OS to boot. Slots that are rejected in the LOCKED
  state might not be rejected in the UNLOCKED state, (e.g. when
  UNLOCKED any key can be used and rollback index failures are
  allowed), so the algorithm used for selecting a slot varies
  depending on what state the device is in.

* If no valid OS (that is, no bootable A/B slot) can be found, the
  device cannot boot and has to enter repair mode. It is
  device-dependent what this looks like.  If the device has a screen
  it must convey this state to the user.

* If the device is LOCKED, only an OS signed by an embedded
  verification key (see the previous section) shall be
  accepted. Additionally, `rollback_index[n]` as stored in the
  verified image must be greater or equal than what's in
  `stored_rollback_index[n]` on the device (for all `n`) and the
  `stored_rollback_index[n]` array is expected to be updated as
  specified in the previous section.
    + If the key used for verification was set by the end user, and
      the device has a screen, it must show a warning with the key
      fingerprint to convey that the device is booting a custom
      OS. The warning must be shown for at least 10 seconds before the
      boot process continues. If the device does not have a screen,
      other ways must be used to convey that the device is booting a
      custom OS (lightbars, LEDs, etc.).

* If the device is UNLOCKED, there is no requirement to check the key
  used to sign the OS nor is there any requirement to check or update
  rollback `stored_rollback_index[n]` on the device. Because of this
  the user must always be shown a warning about verification not
  occurring.
    + It is device-dependent how this is implemented since it depends
      on the device form-factor and intended usage. If the device has
      a screen and buttons (for example if it's a phone) the warning
      is to be shown for at least 10 seconds before the boot process
      continues. If the device does not have a screen, other ways must
      be used to convey that the device is UNLOCKED (lightbars, LEDs,
      etc.).

## Handling dm-verity Errors

By design, hashtree verification errors are detected by the HLOS and
not the bootloader. AVB provides a way to specify how the error should
be handled through the `hashtree_error_mode` parameter in the
`avb_slot_verify()` function. Possible values include

* `AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE` means that the HLOS
  will invalidate the current slot and restart. On devices with A/B
  this would lead to attempting to boot the other slot (if it's marked
  as bootable) or it could lead to a mode where no OS can be booted
  (e.g. some form of repair mode).

* `AVB_HASHTREE_ERROR_MODE_RESTART` means that the OS will restart
  without the current slot being invalidated. Be careful using this
  mode unconditionally as it may introduce boot loops if the same
  hashtree verification error is hit on every boot.

* `AVB_HASHTREE_ERROR_MODE_EIO` means that an `EIO` error will be
  returned to the application.

* `AVB_HASHTREE_ERROR_MODE_LOGGING` means that errors will be logged
   and corrupt data may be returned to applications. This mode should
   be used for **ONLY** diagnostics and debugging. It cannot be used
   unless verification errors are allowed.

The value passed in `hashtree_error_mode` is essentially just passed
on through to the HLOS through the the `androidboot.veritymode` and
`androidboot.vbmeta.invalidate_on_error` kernel command-line
parameters. The HLOS - including the Linux kernel when using
`CONFIG_DM_VERITY_AVB` - will then act upon hashtree verification
errors as specified.

### Which mode should I use for my device?

This depends entirely on the device, how the device is intended to be
used, and the desired user experience.

For example, consider
the
[EIO mode in an earlier version of Android Verified Boot](https://source.android.com/security/verifiedboot/verified-boot) (see
the "Recovering from dm-verity errors" section). In a nutshell this
mode uses `AVB_HASHTREE_ERROR_MODE_RESTART` mode until an error is
encounted and then it switches to `AVB_HASHTREE_ERROR_MODE_EIO` mode
on the reboot. Additionally when in `AVB_HASHTREE_ERROR_MODE_EIO` mode
the user is informed that the device experienced corruption and then
asked to click through a screen to continue.

To implement this mode in a boot loader, a combination of the
`AVB_HASHTREE_ERROR_MODE_RESTART` mode and
`AVB_HASHTREE_ERROR_MODE_EIO` mode could be used along with persistent
storage recording what mode the bootloader is currently in. This would
need to include transition rules e.g. if the kernel indicates that it
rebooted because of a `dm-verity` error the bootloader would need to
transition from the `AVB_HASHTREE_ERROR_MODE_RESTART` mode to the
`AVB_HASHTREE_ERROR_MODE_EIO` mode. Ditto, when the slot is updated
the bootloader needs to transition from the
`AVB_HASHTREE_ERROR_MODE_EIO` mode back to the
`AVB_HASHTREE_ERROR_MODE_RESTART` mode so the user doesn't have to
click through a screen on every boot.

On the other hand, if the device doesn't have a screen or if the HLOS
supports multiple bootable slots simultaneously it may make more sense
to just use `AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE`.

## Android Specific Integration

On Android, the boot loader must set the
`androidboot.verifiedbootstate` parameter on the kernel command-line
to indicate the boot state. It shall use the following values:

* **green**: If in LOCKED state and the key used for verification was not set by the end user.
* **yellow**: If in LOCKED state and the key used for verification was set by the end user.
* **orange**: If in the UNLOCKED state.
