use xbuild::Result;

fn main() -> Result<()> {
    xbuild::build_and_link("bootloader", |lib| {
        lib.import_lib("io")?;

        lib.add_includes([".", "protob"]);

        lib.add_include("../../rust"); // Cyclic dependency

        if cfg!(feature = "emulator") {
            lib.add_source("emulator.c");
        }

        lib.add_defines([
            ("PB_FIELD_16BIT", Some("1")),
            ("PB_ENCODE_ARRAYS_UNPACKED", Some("1")),
            ("PB_VALIDATE_UTF8", Some("1")),
            // Drops nanopb's error message strings (~1 kB of flash). Nothing
            // in the bootloader reads `pb_(i|o)stream_t::errmsg`.
            ("PB_NO_ERRMSG", Some("1")),
        ]);

        // Bare-board build: no display or touch is fitted, so the UI workflows must
        // be skipped. Never enable this path in a production build.
        //
        // This used to also require bootloader_devel, which was wrong in a way that
        // mattered. bootloader_devel is precisely what makes image.c substitute the
        // published development keys for MODEL_BOOTLOADER_KEYS and
        // MODEL_BOARDLOADER_KEYS, so demanding it made "headless" and "signed with
        // keys anyone has" inseparable -- the clause enforced the very weakness it
        // read as guarding against, and blocked activation step 2, whose whole point
        // is a headless bootloader carrying this project's own keys. The clause that
        // actually keeps this path out of a shipped build is !production, and it stays.
        if cfg!(feature = "headless_dev") {
            assert!(
                !cfg!(feature = "production"),
                "headless_dev forbids production: there is no display to show a \
                 confirmation on, so the UI workflows are compiled out"
            );
            lib.add_define("TS5_HEADLESS_DEV", Some("1"));
            lib.add_source("headless_boot_policy.c");
            lib.add_source("authenticator_update_policy.c");
        }

        lib.add_sources([
            "bootui.c",
            "fw_check.c",
            "main.c",
            "ui_helpers.c",
            "version_check.c",
            "workflow/wf_firmware_update.c",
            "workflow/wf_image_upload.c",
            "workflow/wf_wipe_device.c",
            "workflow/wf_get_features.c",
            "workflow/wf_initialize.c",
            "workflow/wf_ping.c",
            "workflow/wf_bootloader.c",
            "workflow/wf_empty_device.c",
            "workflow/wf_auto_update.c",
            "workflow/wf_host_control.c",
            "workflow/wf_ble_pairing_request.c",
            "wire/codec_v1.c",
            "wire/wire_iface_usb.c",
            "wire/wire_iface_ble.c",
            "protob/protob.c",
            "protob/pb/messages.pb.c",
        ]);

        if cfg!(not(feature = "emulator")) {
            if cfg!(feature = "boot_ucb") {
                lib.add_source("header_pq.c");
            } else {
                lib.add_source("header.S");
            }
        }

        if cfg!(feature = "lockable_bootloader") {
            lib.add_source("workflow/wf_unlock_bootloader.c");
        }

        if cfg!(feature = "disable_animation") {
            lib.add_define("DISABLE_ANIMATION", Some("1"));
        }

        if cfg!(feature = "debuglink") {
            lib.add_sources([
                "workflow/debuglink.c",
                "wire/debug_iface_usb.c",
                "protob/protob_debug.c",
                "protob/pb/messages-debug.pb.c",
            ]);
        }

        // nanopb library
        lib.add_include("../../../vendor/nanopb");
        lib.add_sources_in_dir(
            "../../../vendor/nanopb/",
            ["pb_common.c", "pb_decode.c", "pb_encode.c"],
        );

        Ok(())
    })
}
