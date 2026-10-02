use xbuild::{Result, bail, bail_unsupported};

#[path = "tools/usb_allocation.rs"]
mod usb_allocation;

fn main() -> Result<()> {
    if cfg!(feature = "authenticator_test_backend") && !cfg!(feature = "emulator") {
        bail!("authenticator test backend is emulator-only");
    }
    if cfg!(feature = "authenticator_test_presence") && !cfg!(feature = "emulator") {
        bail!("authenticator test presence is emulator-only");
    }
    if cfg!(feature = "production") {
        if cfg!(any(
            feature = "authenticator_test_presence",
            feature = "authenticator_test_backend",
            feature = "authenticator_integration_credentials"
        )) {
            bail!("authenticator test features are forbidden in production");
        }
        // Named separately so the refusal says what it refused. A production
        // image that confirmed operations nobody confirmed would be the one
        // failure this whole project is built to prevent.
        if cfg!(feature = "authenticator_assumed_presence") {
            bail!("assumed presence is forbidden in production");
        }
        usb_allocation::approved_identity()?;
    }

    xbuild::build_and_link("authenticator", |lib| {
        lib.add_define("AUTHENTICATOR", Some("1"));
        for (enabled, name) in [
            (
                cfg!(feature = "authenticator_test_presence"),
                "AUTH_TEST_PRESENCE",
            ),
            (
                cfg!(feature = "authenticator_test_backend"),
                "AUTH_TEST_BACKEND",
            ),
            (
                cfg!(feature = "authenticator_integration_credentials"),
                "AUTH_INTEGRATION_CREDENTIALS",
            ),
            (
                cfg!(feature = "authenticator_assumed_presence"),
                "AUTH_ASSUMED_PRESENCE",
            ),
            (cfg!(feature = "production"), "AUTH_PRODUCTION"),
        ] {
            if enabled {
                lib.add_define(name, Some("1"));
            }
        }
        lib.import_lib("io")?;
        lib.import_lib("upymod")?;
        lib.add_include("../../rust");

        if cfg!(feature = "emulator") {
            lib.add_sources(["src/unix/main.c", "src/unix/main_main.c"]);
        } else if cfg!(feature = "mcu_stm32u5") {
            lib.add_sources([
                "src/stm32/main.c",
                "src/stm32/audit_metadata.c",
                "src/stm32/header.S",
                "src/stm32/coreapp_header.S",
            ]);
            let model_id = xbuild::current_model_id()?;
            if model_id != "T3T1" {
                bail!("authenticator is supported only on T3T1");
            }
            // Deliberately not xbuild::vendor_header_path(.., "firmware"). That header
            // carries fw_type VENDOR_FW_TYPE_RESERVED and the vendor string
            // "DEV ONLY, DO NOT USE!" -- the very header ordinary Trezor firmware uses
            // in a devel build -- so an image built against it is indistinguishable
            // from ordinary firmware in every field a bootloader can authenticate.
            // This product's bootloader refuses precisely that case: see
            // authenticator_update_check, which requires VENDOR_FW_TYPE_AUTHENTICATOR.
            // Keeping the shared header as the default would mean the ordinary build
            // produces an image this device's own bootloader rejects, with the fix
            // living in an environment variable nobody is obliged to set. So the
            // authenticator's own header is the default and VENDOR_HEADER only
            // overrides it.
            let vendor_header = match std::env::var("VENDOR_HEADER") {
                Ok(path) if !path.is_empty() => std::path::PathBuf::from(path),
                _ if cfg!(feature = "bootloader_devel") => std::path::PathBuf::from(format!(
                    "../../models/{model_id}/vendorheader/\
                     vendorheader_aylo_DO_NOT_SIGN_signed_dev.bin"
                )),
                // Activation step 2 produced this one: the same header, signed by the
                // project's own bootloader keys instead of the published development
                // ones. A build without bootloader_devel is the only build whose
                // bootloader checks those keys, so the two names are not
                // interchangeable and picking the wrong one yields an image the device
                // refuses.
                _ => std::path::PathBuf::from(format!(
                    "../../models/{model_id}/vendorheader/vendorheader_aylo_signed_prod.bin"
                )),
            };
            lib.embed_binary(vendor_header, "vendorheader")?;
            let kernel = xbuild::cargo_profile_dir()?.join("kernel.bin");
            lib.embed_binary(kernel, "kernel")?;
            // No embedded bootloader, and no src/stm32/boot_image_embdata.c to describe
            // one. Ordinary firmware embeds a compressed bootloader and installs it from
            // main() when it differs; this project never did, because nothing here calls
            // boot_image_check or boot_image_replace. The copy was 128 kB of payload that
            // could not run, and worse, it read as though shipping a firmware image also
            // shipped a bootloader. It does not.
            //
            // It is not merely unwired, it should stay unwired on this hardware. T3T1 does
            // not enable the boot_ucb feature, so boot_image_replace() takes the branch in
            // sec/image/stm32/boot_image.c that calls flash_area_erase(&BOOTLOADER_AREA)
            // and then streams the decompressed image in. Power lost inside that window
            // leaves no bootloader at all, and this device has no screen on which to say
            // so. Today SWD recovers it. After activation step 4 raises RDP to 1, debug
            // cannot write flash and the only exit is a mass erase, so a self-update would
            // be a recurring chance of unrecoverable failure with no recovery path -- worse
            // than a bootloader that simply cannot change.
            //
            // The consequence is recorded as a precondition of step 4 in
            // docs/authenticator/activation.md: sealing freezes the bootloader. A safe
            // in-field path needs boot_ucb, where the boardloader performs the swap, and
            // that is a boardloader change, not a firmware one.
        } else {
            bail_unsupported!();
        }
        Ok(())
    })
}
