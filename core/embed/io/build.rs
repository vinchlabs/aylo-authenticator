use xbuild::{Result, build_mods};

#[path = "app_arena/build.rs"]
mod app_arena;
#[path = "auth_presence/build.rs"]
mod auth_presence;
#[path = "backlight/build.rs"]
mod backlight;
#[path = "ble/build.rs"]
mod ble;
#[path = "button/build.rs"]
mod button;
#[path = "display/build.rs"]
mod display;
#[path = "gfx/build.rs"]
mod gfx;
#[path = "haptic/build.rs"]
mod haptic;
#[path = "nfc/build.rs"]
mod nfc;
#[path = "notify/build.rs"]
mod notify;
#[path = "nrf/build.rs"]
mod nrf;
#[path = "power_manager/build.rs"]
mod power_manager;
#[path = "rgb_led/build.rs"]
mod rgb_led;
#[path = "sbu/build.rs"]
mod sbu;
#[path = "sdcard/build.rs"]
mod sdcard;
#[path = "suspend/build.rs"]
mod suspend;
#[path = "touch/build.rs"]
mod touch;
#[path = "translations/build.rs"]
mod translations;
#[path = "tsqueue/build.rs"]
mod tsqueue;
#[path = "usb/build.rs"]
mod usb;

fn main() -> Result<()> {
    xbuild::build(|lib| {
        if cfg!(feature = "authenticator") {
            lib.add_define("AUTHENTICATOR", Some("1"));
        }
        lib.import_lib("sec")?;

        build_mods!(
            lib,
            [
                app_arena if cfg!(feature = "app_loading"),
                auth_presence if cfg!(feature = "auth_presence"),
                backlight if cfg!(feature = "backlight"),
                ble if cfg!(feature = "ble"),
                button if cfg!(feature = "button"),
                display if cfg!(feature = "display"),
                gfx if cfg!(feature = "display"),
                haptic if cfg!(feature = "haptic"),
                notify,
                nfc if cfg!(feature = "nfc"),
                nrf if cfg!(feature = "nrf"),
                power_manager if cfg!(any(feature = "power_manager", feature = "pmic")),
                rgb_led if cfg!(feature = "rgb_led"),
                sbu if cfg!(feature = "sbu"),
                sdcard if cfg!(feature = "sd_card"),
                suspend if cfg!(feature = "suspend"),
                touch if cfg!(feature = "touch"),
                // Excluded from the authenticator: translations_write() and
                // translations_erase() operate on ASSETS_AREA, which on this
                // project holds the third vault replica. A headless
                // authenticator has no strings to localise, so the whole
                // subsystem is left out rather than merely unused.
                translations if cfg!(not(feature = "authenticator")),
                tsqueue,
                usb if cfg!(feature = "usb"),
            ]
        );

        if cfg!(not(feature = "emulator")) && cfg!(not(feature = "kernel_mode")) {
            // Add syscall stubs when linking in in unprivileged mode
            lib.add_source("../sys/syscall/stm32/syscall_stubs.c");
        }

        if cfg!(feature = "test") {
            // Add syscall stubs when linking in the emulator, which doesn't have a
            // real kernel to link against.
            lib.add_source("src/test_setup.c");
        }

        Ok(())
    })
}
